"""MudraIDMiddleware — Starlette/FastAPI middleware that enforces MudraID scopes.

This is the keystone module. It runs in one of two mutually-exclusive modes,
selected by the ``mode`` constructor argument:

  - **``mode="v1"`` (default)** — the static-YAML route-scope enforcement
    described below. Unchanged; this is the locked V1 contract.
  - **``mode="v2"``** — the portable V2 enforcement control loop
    (``_v2_control_loop``) runs before the handler: reserved ``x-mudraid-*``
    headers are stripped first, the request is classified, and a live
    ``/decide`` call (deny-closed on timeout/error/no-bundle/unmapped) gates the
    handler. See :mod:`mudraid_middleware.v2`. V2 is a strict, additive opt-in —
    a successful V1 JWT check is NEVER inferred as V2 enforcement.

V1 per-request flow:

  1. Match the request's (method, path) against the rules from
     ``mudraid_scopes.yaml`` (loaded lazily on first dispatch).
  2. If no rule matches → 404. Routes not in the YAML are invisible
     to agents — admin endpoints especially.
  3. If the rule is ``public: true`` → forward straight to the
     route handler. (M5.7)
  4. If the rule is ``skip: true`` → 404, same as 'no rule matched'.
     Used to hide admin routes from agents while still keeping them
     reachable from the platform's own front-end. (M5.8)
  5. Otherwise the rule has a ``scope``. We:
       a. Extract the ``Authorization: Bearer <jwt>`` header.
       b. Validate the JWT (signature + iss + aud + exp + nbf + iat)
          via :class:`JwtValidator`.
       c. Check the route's required scope is present in the JWT's
          ``scopes`` claim.
       d. Forward to the handler if both gates pass.
  6. Failures produce a structured JSON error response (M5.9) with
     a stable ``error_code`` so platforms can show consistent
     messaging to agents.

Locked behaviour (don't change without an explicit decision):

  - **Lazy bootstrap.** YAML + JwksClient + JwtValidator are built
    on the FIRST dispatch, not in ``__init__``. Construction is
    side-effect-free so a missing YAML at app-import time doesn't
    crash; the failure surfaces on the first request instead.
  - **Single in-flight bootstrap.** Under thundering-herd traffic
    at boot, all concurrent first requests are coalesced via
    ``asyncio.Lock`` so the YAML is parsed exactly once.
  - **Authorization header is case-insensitive on scheme.** Per
    RFC 7235 § 2.1, credential schemes are case-insensitive;
    ``Bearer`` and ``bearer`` are both accepted. The token itself
    is taken verbatim.
  - **No-rule path returns 404, not 403.** A route absent from the
    YAML is treated as non-existent from the agent's perspective;
    revealing that "the route exists but you can't use it" would
    leak topology to the agent.
  - **JWKS errors are 500, not 401.** A JWT we can't verify is
    different from a JWT we verified and rejected. The former is
    operationally significant (something's wrong on our side); the
    latter is normal failure.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Sequence
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from mudraid_middleware._jwks_client import JwksClient
from mudraid_middleware._jwt_validator import JwtValidator
from mudraid_middleware._route_matcher import RouteMatcher
from mudraid_middleware._v2_control_loop import (
    DecideResult,
    V2Decision,
    V2RequestFacts,
    evaluate_v2,
    is_reserved_header,
    valid_tool_name,
)
from mudraid_middleware._yaml_loader import ScopesYaml, load_scopes_yaml
from mudraid_middleware.exceptions import (
    MudraIDInvalidTokenError,
    MudraIDJwksError,
    MudraIDScopesYamlError,
)
from mudraid_middleware.v2 import V2Config

_logger = logging.getLogger("mudraid_middleware")

_DEFAULT_YAML_PATH = "mudraid_scopes.yaml"
_DEFAULT_JWKS_URL = "https://api.staging.mudraid.ai/.well-known/jwks.json"

# Reason (from JwtValidator) → stable error_code surfaced to the agent.
# Locked so a future renaming of internal reasons doesn't break a
# platform's error-handling code.
_REASON_TO_ERROR_CODE = {
    "malformed": "INVALID_TOKEN",
    "expired": "EXPIRED_TOKEN",
    "not_yet_valid": "TOKEN_NOT_YET_VALID",
    "wrong_audience": "WRONG_AUDIENCE",
    "wrong_issuer": "WRONG_ISSUER",
    "invalid_signature": "INVALID_TOKEN",
}


class MudraIDMiddleware(BaseHTTPMiddleware):
    """Starlette / FastAPI middleware enforcing MudraID-issued JWTs.

    Args:
        app: The ASGI app to wrap.
        scopes_yaml_path: Override the default location of
            ``mudraid_scopes.yaml``. Defaults to ``./mudraid_scopes.yaml``
            resolved against the process working directory. (V1 mode only.)
        jwks_url: Override MudraID's JWKS endpoint. Defaults to the
            ``MUDRAID_JWKS_URL`` env var, falling back to
            ``https://api.staging.mudraid.ai/.well-known/jwks.json``. (V1 mode only.)
        mode: ``"v1"`` (default) selects the static route-scope enforcement;
            ``"v2"`` selects the V2 control loop and REQUIRES ``v2_config``.
            V1 behaviour is byte-identical whether or not V2 is available.
        v2_config: The :class:`~mudraid_middleware.v2.V2Config` selecting V2
            mode. Must be supplied iff ``mode="v2"``; must be absent otherwise.
    """

    def __init__(
        self,
        app: ASGIApp,
        scopes_yaml_path: str | None = None,
        jwks_url: str | None = None,
        expected_issuer: str | Sequence[str] | None = None,
        mode: str = "v1",
        v2_config: V2Config | None = None,
    ) -> None:
        super().__init__(app)
        if mode not in ("v1", "v2"):
            raise ValueError(f"mode must be 'v1' or 'v2', not {mode!r}")
        if mode == "v2" and v2_config is None:
            raise ValueError("mode='v2' requires a v2_config")
        if mode == "v1" and v2_config is not None:
            raise ValueError("v2_config is only valid with mode='v2'")
        self._mode = mode
        self._v2_config = v2_config
        self._scopes_yaml_path = scopes_yaml_path or _DEFAULT_YAML_PATH
        self._jwks_url = jwks_url or os.getenv("MUDRAID_JWKS_URL", "").strip() or _DEFAULT_JWKS_URL
        # Issuer the validator will accept. Defaults to None → the validator's
        # own default single issuer. A transition SET (for a verifier-before-
        # issuer rollout, charter §16) may be supplied here or via the
        # comma-separated env var MUDRAID_EXPECTED_ISSUERS (0 → default,
        # 1 → single issuer, ≥2 → accept any of them).
        self._expected_issuer = self._resolve_expected_issuer(expected_issuer)
        # Bootstrapped state — all built lazily on first dispatch.
        self._scopes: ScopesYaml | None = None
        self._matcher: RouteMatcher | None = None
        self._validator: JwtValidator | None = None
        self._bootstrap_lock = asyncio.Lock()

    @staticmethod
    def _resolve_expected_issuer(
        expected_issuer: str | Sequence[str] | None,
    ) -> str | Sequence[str] | None:
        """Resolve the accepted issuer(s): explicit arg wins, else env.

        ``MUDRAID_EXPECTED_ISSUERS`` is comma-separated:
          - unset/empty → ``None`` (validator uses its default single issuer)
          - one value   → that single issuer (str)
          - two or more → a tuple accepted as a transition set
        """
        if expected_issuer is not None:
            return expected_issuer
        raw = os.getenv("MUDRAID_EXPECTED_ISSUERS", "")
        values = tuple(v.strip() for v in raw.split(",") if v.strip())
        if not values:
            return None
        if len(values) == 1:
            return values[0]
        return values

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # V2 mode is a wholly separate control loop; it never touches the
        # static YAML bootstrap below. V1 mode falls through unchanged.
        if self._mode == "v2":
            return await self._dispatch_v2(request, call_next)

        # 1. Ensure the four building blocks are wired. A YAML schema
        #    error here is an operator-side configuration problem;
        #    we turn it into a structured 500 instead of letting
        #    Starlette throw a generic uncaught exception. The
        #    failure is NOT cached — the next request will re-attempt
        #    the bootstrap so an operator who fixes the YAML doesn't
        #    have to restart the process.
        try:
            await self._ensure_bootstrapped()
        except MudraIDScopesYamlError as exc:
            _logger.error("MudraIDMiddleware bootstrap failed: %s", exc)
            return _error(
                500,
                "MIDDLEWARE_NOT_READY",
                "scope configuration is unavailable; check the server logs",
            )
        # An explicit guard rather than ``assert``: the matcher / validator
        # are guaranteed non-None after a successful ``_ensure_bootstrapped``,
        # but an ``assert`` is stripped under ``python -O`` whereas this
        # check survives and gives mypy the same narrowing.
        if self._matcher is None or self._validator is None:  # pragma: no cover
            return _error(500, "MIDDLEWARE_NOT_READY", "internal bootstrap invariant violation")

        # 2. Match (method, path) against the YAML's route list.
        rule = self._matcher.match(request.method, request.url.path)
        if rule is None:
            # Not covered by mudraid_scopes.yaml — treat as nonexistent
            # for agents. A platform front-end accessing the same path
            # outside this middleware (e.g. on a different port) is
            # unaffected.
            return _route_not_found()

        # 3 / 4. Public and skip handling — early exits, no token check.
        if rule.public:
            return await call_next(request)
        if rule.skip:
            return _route_not_found()

        # 5. Scope-gated route. Pull the Bearer token off the request.
        token = _extract_bearer_token(request)
        if token is None:
            return _error(
                401,
                "MISSING_TOKEN",
                "Authorization header missing or not in 'Bearer <token>' form",
            )

        # 6a. Verify the JWT.
        try:
            claims = await self._validator.validate(token)
        except MudraIDInvalidTokenError as exc:
            error_code = _REASON_TO_ERROR_CODE.get(exc.reason, "INVALID_TOKEN")
            return _error(401, error_code, str(exc))
        except MudraIDJwksError as exc:
            # We couldn't verify — distinct from "we verified and
            # rejected". The agent / operator needs to retry, not
            # fix their credentials.
            _logger.warning("JWKS unavailable while verifying request: %s", exc)
            return _error(500, "JWKS_UNAVAILABLE", "could not verify token signature")

        # 6b. Scope membership. The required scope MUST be present in
        # the token's `scopes` claim.
        token_scopes = claims.get("scopes")
        if not isinstance(token_scopes, list) or rule.scope not in token_scopes:
            return _error(
                403,
                "MISSING_SCOPE",
                f"required scope '{rule.scope}' not present in token",
            )

        # 7. Every gate passed. Forward.
        return await call_next(request)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    async def _ensure_bootstrapped(self) -> None:
        if self._matcher is not None and self._validator is not None:
            return
        async with self._bootstrap_lock:
            if self._matcher is not None and self._validator is not None:
                return
            scopes = load_scopes_yaml(self._scopes_yaml_path)
            jwks_client = JwksClient(jwks_url=self._jwks_url)
            # Pass expected_issuer only when configured, so the default
            # construction (single literal issuer) stays byte-identical.
            if self._expected_issuer is None:
                validator = JwtValidator(
                    jwks_client=jwks_client,
                    expected_audience=scopes.platform_id,
                )
            else:
                validator = JwtValidator(
                    jwks_client=jwks_client,
                    expected_audience=scopes.platform_id,
                    expected_issuer=self._expected_issuer,
                )
            # Publish atomically — every cross-field invariant
            # (matcher built from same scopes the validator is bound
            # to) holds at the moment we expose them.
            self._scopes = scopes
            self._matcher = RouteMatcher(scopes.routes)
            self._validator = validator
            _logger.info(
                "MudraIDMiddleware bootstrapped: platform_id=%s, %d routes",
                scopes.platform_id,
                len(scopes.routes),
            )

    # ------------------------------------------------------------------
    # V2 mode
    # ------------------------------------------------------------------

    async def _dispatch_v2(self, request: Request, call_next: Any) -> Response:
        """Run the V2 enforcement control loop before the handler.

        The DECISION tree lives in :func:`evaluate_v2`; this method only
        extracts facts from the live request, drives the injected
        :class:`DecideClient`, and translates the resulting
        :class:`V2Decision` into either a forward (handler runs) or a
        structured deny. It never optimistically allows.
        """
        cfg = self._v2_config
        assert cfg is not None  # guaranteed by the constructor's mode check

        # 0. Unprotected surface: pass through untouched — nothing is stripped
        #    or decided (mirrors the contract's surface_not_protected outcome).
        protected = cfg.is_protected(request.url.path)
        if not protected:
            return await call_next(request)

        # 1. Strip reserved x-mudraid-* headers FIRST — before ANY evaluation,
        #    and even on requests that will be denied. Client-supplied trusted
        #    context is never accepted as an input fact.
        presented = _strip_reserved_headers(request)

        # 2. Fact extraction. Only a protected POST needs a body read + parse;
        #    control verbs and non-POST methods are classified before framing,
        #    exactly as the control loop's branch order requires.
        body_readable = True
        body_too_large = False
        json_shape = "not_json"
        jsonrpc: str | None = None
        rpc_method: str | None = None
        tool_name: str | None = None
        action: str | None = None
        action_mapped = False

        if protected and request.method.upper() == "POST":
            body, body_too_large, body_readable = await _read_bounded_body(
                request, cfg.max_body_bytes
            )
            if body_readable and not body_too_large:
                json_shape, payload = _classify_json(body)
                if json_shape == "object" and payload is not None:
                    raw_jsonrpc = payload.get("jsonrpc")
                    jsonrpc = raw_jsonrpc if isinstance(raw_jsonrpc, str) else None
                    raw_method = payload.get("method")
                    rpc_method = raw_method if isinstance(raw_method, str) else None
                    params = payload.get("params")
                    if isinstance(params, dict):
                        raw_name = params.get("name")
                        tool_name = raw_name if isinstance(raw_name, str) else None
                    if rpc_method == "tools/call" and valid_tool_name(tool_name):
                        # Exact, case-sensitive canonical action resolution.
                        assert tool_name is not None
                        action = cfg.decide_client.resolve_action(tool_name)
                        action_mapped = action is not None

        facts = V2RequestFacts(
            protected=protected,
            reserved_headers_presented=presented,
            bundle_active=bool(cfg.decide_client.bundle_active),
            method=request.method,
            body_readable=body_readable,
            body_too_large=body_too_large,
            json_shape=json_shape,
            jsonrpc=jsonrpc,
            rpc_method=rpc_method,
            tool_name=tool_name,
            action_mapped=action_mapped,
            action=action,
        )

        decision = await evaluate_v2(facts, self._make_decide(cfg))

        if decision.forward:
            # Trusted context is injected ONLY after a bound allow.
            _inject_trusted_context(request, decision.trusted_context)
            return await call_next(request)
        return _v2_error(decision)

    def _make_decide(self, cfg: V2Config) -> Any:
        """Wrap the injected client's ``decide`` so any failure deny-closes.

        A timeout or transport error must never propagate as an exception that
        could bubble past the control loop and be mistaken for a soft failure;
        it is normalized to a deny-closed :class:`DecideResult`. No token or
        secret is logged — only the exception type name.
        """

        async def _decide(action: str) -> DecideResult:
            try:
                return await cfg.decide_client.decide(action)
            except asyncio.TimeoutError:
                return DecideResult("timeout")
            except Exception as exc:  # noqa: BLE001 — deny-closed on ANY failure
                _logger.warning("V2 /decide unavailable: %s", type(exc).__name__)
                return DecideResult("error")

        return _decide


# ---- helpers (module-level so dispatch stays readable) -------------------


def _extract_bearer_token(request: Request) -> str | None:
    """Return the token portion of the ``Authorization`` header.

    Returns ``None`` when the header is missing, doesn't start with
    ``Bearer`` (case-insensitive), or has an empty token after the
    scheme. The middleware treats all three the same — there's no
    credential to validate.
    """
    raw = request.headers.get("Authorization")
    if not raw:
        return None
    parts = raw.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0], parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _route_not_found() -> Response:
    """Single 404 shape for both 'not in YAML' and 'skip: true' rules.

    Locked: the agent must NOT be able to distinguish these. Revealing
    that the route exists-but-is-hidden would leak topology.
    """
    return _error(404, "ROUTE_NOT_FOUND", "no agent route at this path")


def _error(status_code: int, error_code: str, message: str) -> Response:
    """Build the structured error response shape locked in docs/openapi.yaml.

    Body: ``{"error_code": "...", "message": "..."}``. No stack traces,
    no upstream library detail — just the stable code + a human-readable
    message safe to show in an agent's logs.
    """
    return JSONResponse(
        status_code=status_code,
        content={"error_code": error_code, "message": message},
    )


# ---- V2-mode helpers -----------------------------------------------------


def _v2_error(decision: V2Decision) -> Response:
    """Render a denied :class:`V2Decision` in the locked error-body shape.

    Reuses :func:`_error`, so V2 denies carry the same
    ``{"error_code", "message"}`` shape platforms already build alerting on.
    The ``error_code`` values mirror the portable adapter-decision contract so
    an agent sees consistent codes across Kong and this middleware.
    """
    error_code = decision.error_code or "ENFORCE_DENIED"
    return _error(decision.http_status, error_code, decision.message)


def _strip_reserved_headers(request: Request) -> tuple[str, ...]:
    """Remove every reserved ``x-mudraid-*`` header from the live request.

    Mutates ``request.scope["headers"]`` in place so the downstream handler
    never observes client-forged trusted context, and returns the names that
    were presented (original case preserved) so the control loop can record
    what was stripped. Called FIRST, before any evaluation.
    """
    presented: list[str] = []
    kept: list[tuple[bytes, bytes]] = []
    for raw_name, raw_value in request.scope.get("headers", []):
        name = raw_name.decode("latin-1")
        if is_reserved_header(name):
            presented.append(name)
            continue
        kept.append((raw_name, raw_value))
    request.scope["headers"] = kept
    return tuple(presented)


def _inject_trusted_context(request: Request, trusted_context: tuple[tuple[str, str], ...]) -> None:
    """Append trusted context headers to the live request (allow path only).

    The reserved-header strip has already removed any client-supplied
    ``x-mudraid-*`` headers, so the handler sees ONLY the values the middleware
    itself injects after a bound allow.
    """
    headers = list(request.scope.get("headers", []))
    for name, value in trusted_context:
        headers.append((name.encode("latin-1"), value.encode("latin-1")))
    request.scope["headers"] = headers


async def _read_bounded_body(request: Request, max_bytes: int) -> tuple[bytes, bool, bool]:
    """Read the request body under a bounded-framing limit.

    Returns ``(body, too_large, readable)``. A ``Content-Length`` over the limit
    is rejected without reading; an actual body over the limit is rejected after
    reading; a body that cannot be read (client disconnect, etc.) is reported
    unreadable. Reading here does not consume the body for the downstream
    handler — Starlette caches it on the request.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > max_bytes:
                return b"", True, True
        except ValueError:
            pass
    try:
        body = await request.body()
    except Exception:  # noqa: BLE001 — any read failure is "unreadable", deny-closed
        return b"", False, False
    if len(body) > max_bytes:
        return b"", True, True
    return body, False, True


def _classify_json(body: bytes) -> tuple[str, dict[str, Any] | None]:
    """Classify a raw body as ``object`` / ``array`` / ``scalar`` / ``not_json``.

    Only an ``object`` yields a parsed payload; the other shapes are terminal
    (a JSON array is a batch, rejected wholesale — never partially evaluated).
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return "not_json", None
    if isinstance(parsed, dict):
        return "object", parsed
    if isinstance(parsed, list):
        return "array", None
    return "scalar", None

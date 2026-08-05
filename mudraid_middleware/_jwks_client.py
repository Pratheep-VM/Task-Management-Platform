"""Fetch + cache MudraID's JWKS for JWT verification.

The middleware verifies every incoming JWT against MudraID's
published key set rather than calling MudraID on each request.
This module is responsible for keeping that key set fresh:

  - **Lazy bootstrap.** The first ``get_key`` call fetches JWKS.
    Construction is side-effect-free so a misconfigured startup
    doesn't crash on import.
  - **1-hour TTL** (configurable). After the TTL expires the next
    ``get_key`` triggers a refresh.
  - **Reactive refresh on unknown kid.** Locked decision D4 from
    the Phase 3 plan: a JWT carrying a ``kid`` we don't have
    triggers ONE refresh attempt, then a re-lookup. If the kid is
    still missing after refresh, ``MudraIDJwksError`` is raised —
    we never silently pass an unverifiable token through.
  - **Single in-flight refresh.** Concurrent ``get_key`` calls
    that all miss the cache coalesce into one HTTP request via
    ``asyncio.Lock``; the late-arrivers re-read the cache after
    the holder's fetch publishes.

The module is async because the middleware host (Starlette's
``BaseHTTPMiddleware``) is async — a blocking sync HTTP call here
would stall the event loop on every cold-cache request.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
from jwt.algorithms import RSAAlgorithm

from mudraid_middleware.exceptions import MudraIDJwksError

_DEFAULT_TTL_SEC = 3600.0
_DEFAULT_TIMEOUT_SEC = 5.0


class JwksClient:
    """Async JWKS fetcher with a TTL cache and reactive-refresh."""

    def __init__(
        self,
        jwks_url: str,
        cache_ttl_sec: float = _DEFAULT_TTL_SEC,
        timeout_sec: float = _DEFAULT_TIMEOUT_SEC,
    ) -> None:
        if not jwks_url:
            raise ValueError("jwks_url is required")
        self._url = jwks_url
        self._ttl = cache_ttl_sec
        self._timeout = timeout_sec
        # kid -> JWK dict. Empty means "not yet bootstrapped" — but
        # so does "bootstrapped against an empty key set", so don't
        # treat emptiness as a stale signal; use ``_fetched_at``.
        self._cache: dict[str, dict[str, Any]] = {}
        # kid -> parsed public-key object. A memoised view of ``_cache``,
        # populated lazily on first lookup and reset atomically alongside
        # ``_cache`` on every ``_fetch`` (see ``_fetch``). Tying it to the
        # same lifecycle is the security-critical bit: when a key is rotated
        # or revoked out of JWKS, its parsed form is dropped in the same swap,
        # so a removed key can never keep verifying tokens past the JWKS TTL.
        self._parsed: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> dict[str, Any]:
        """Return the JWK whose ``kid`` matches.

        Fetches JWKS on first call. Triggers a refresh if the cache
        is stale OR if ``kid`` isn't in it. Raises
        :class:`MudraIDJwksError` when the kid is unknown even after
        a refresh — the middleware translates this to a 401 with a
        "token signature unverifiable" reason.
        """
        # Fast path: cache fresh AND kid known — no lock needed.
        if self._is_fresh() and kid in self._cache:
            return self._cache[kid]

        async with self._lock:
            # Re-check under the lock. Another coroutine may have
            # refreshed while we were waiting; if so, prefer its
            # work rather than re-fetching.
            if (not self._is_fresh()) or kid not in self._cache:
                await self._fetch()

            jwk = self._cache.get(kid)
            if jwk is None:
                raise MudraIDJwksError(
                    f"JWT signed with unknown kid {kid!r}; "
                    "key not present in MudraID JWKS even after refresh"
                )
            return jwk

    async def get_public_key(self, kid: str) -> Any:
        """Return the *parsed* public key for ``kid``.

        Wraps :meth:`get_key` (which owns all freshness / reactive-refresh /
        unknown-kid trust logic) and memoises the expensive
        ``RSAAlgorithm.from_jwk`` parse so it runs once per key per JWKS
        refresh instead of once per request. The parse cache shares
        ``get_key``'s lifecycle exactly: ``_fetch`` resets ``_parsed`` in the
        same atomic swap as ``_cache``, so a rotated/revoked key drops its
        parsed form too.

        A malformed JWK raises here on lookup (``from_jwk`` propagates),
        matching the previous behaviour where the validator parsed inline.
        """
        jwk = await self.get_key(kid)
        # No ``await`` between this read and the write below, so the
        # ``_parsed`` dict we populate is guaranteed to be the one published
        # by the fetch that produced ``jwk`` — no cross-refresh mixing.
        cached = self._parsed.get(kid)
        if cached is not None:
            return cached
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        self._parsed[kid] = public_key
        return public_key

    async def refresh(self) -> None:
        """Force a JWKS fetch regardless of cache freshness.

        Provided as an operator hook — the middleware doesn't call
        this on the hot path. Useful for ops-driven rotation drills
        and for tests.
        """
        async with self._lock:
            await self._fetch()

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _is_fresh(self) -> bool:
        return self._fetched_at > 0.0 and (time.time() - self._fetched_at) < self._ttl

    async def _fetch(self) -> None:
        """Replace ``self._cache`` with a freshly-fetched JWKS.

        Called only from inside the lock. The cache is replaced
        atomically: either every kid in the new response is present
        afterwards, or — if the fetch raises — the cache is left
        untouched and the exception propagates.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(self._url)
        except httpx.HTTPError as exc:
            raise MudraIDJwksError(f"could not fetch JWKS from {self._url}: {exc}") from exc

        if response.status_code != 200:
            raise MudraIDJwksError(
                f"JWKS endpoint returned status {response.status_code} " f"from {self._url}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise MudraIDJwksError(
                f"JWKS endpoint returned non-JSON body from {self._url}"
            ) from exc

        keys = payload.get("keys") if isinstance(payload, dict) else None
        if not isinstance(keys, list):
            raise MudraIDJwksError(f"JWKS response is missing a 'keys' array (from {self._url})")

        new_cache: dict[str, dict[str, Any]] = {}
        for entry in keys:
            if not isinstance(entry, dict):
                # Tolerate malformed entries — drop them silently.
                # Verification will fail loudly on lookup if the
                # JWT references one of them.
                continue
            kid = entry.get("kid")
            if isinstance(kid, str) and kid:
                new_cache[kid] = entry

        # Atomic swap. Failures above prevent us from reaching here
        # so we never publish a partial cache. ``_parsed`` is reset to empty
        # in the SAME swap so no parsed key outlives its JWK entry — keys
        # rotated/revoked out of this fetch can never be served from the
        # parse cache afterwards.
        self._cache = new_cache
        self._parsed = {}
        self._fetched_at = time.time()

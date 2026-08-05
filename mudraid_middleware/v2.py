"""Public V2-mode configuration surface for :class:`MudraIDMiddleware`.

``mode="v2"`` runs the V2 enforcement control loop (see ``_v2_control_loop``)
before the wrapped handler, instead of the static V1 route-scope check. V2 mode
is a strict, additive OPT-IN: V1 remains the default and is unchanged.

The two things V2 mode needs that V1 doesn't are supplied here:

  - a :class:`DecideClient` — the seam onto the platform's signed bundle
    (which surfaces are protected / which tool names map to a canonical action)
    and its live ``/decide`` authority. Injecting it keeps the middleware's
    tests hermetic — a fake client needs no network;
  - a small amount of transport policy (which paths are protected, the bounded
    body limit), carried by :class:`V2Config`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from mudraid_middleware._v2_control_loop import DecideResult

__all__ = ["DecideClient", "DecideResult", "V2Config"]

#: Default bounded-framing limit for a request body (1 MiB). A body larger than
#: this is denied at the framing layer, never partially evaluated.
_DEFAULT_MAX_BODY_BYTES = 1_048_576


@runtime_checkable
class DecideClient(Protocol):
    """The seam onto the platform's signed bundle and live ``/decide`` authority.

    An implementation is injected into :class:`V2Config`; the middleware never
    constructs one itself, so tests can pass a fake with no network. The three
    members map 1:1 onto the control loop's decision facts:

      - :attr:`bundle_active` — is a verified signed bundle currently active?
        When ``False`` the control loop fails CLOSED (503), never optimistically
        allowing.
      - :meth:`resolve_action` — the EXACT, case-sensitive canonical action a
        ``tools/call`` tool name maps to, or ``None`` when unmapped (→ deny).
        Never fuzzy / prefix / regex.
      - :meth:`decide` — the live authority call for a mapped action. Any
        timeout / transport error must be surfaced as a failure
        :class:`DecideResult` (or raised — the middleware wraps the call and
        deny-closes on any exception).
    """

    @property
    def bundle_active(self) -> bool:
        """Whether a verified signed bundle is currently active."""

    def resolve_action(self, tool_name: str) -> str | None:
        """Exact canonical action for ``tool_name``, or ``None`` if unmapped."""

    async def decide(self, action: str) -> DecideResult:
        """Call the live ``/decide`` authority for a mapped canonical action."""


@dataclass(frozen=True)
class V2Config:
    """Configuration selecting and parameterizing V2 mode.

    Args:
        decide_client: The injected :class:`DecideClient` seam. Required.
        protected_paths: Path prefixes whose requests run the V2 control loop.
            ``None`` (default) treats EVERY route as a protected surface. A path
            not covered here passes through untouched (nothing stripped, nothing
            decided) — the equivalent of the contract's unprotected surface.
        max_body_bytes: Bounded-framing limit for the request body. A body over
            this (by ``Content-Length`` or actual size) denies with 413.
        public_methods: JSON-RPC control/discovery methods allowed to pass a
            protected surface without a tool decision. Defaults to the contract's
            allowlist (``initialize``, ``ping``, ``tools/list``, …).
    """

    decide_client: DecideClient
    protected_paths: tuple[str, ...] | None = None
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES
    public_methods: frozenset[str] | None = None

    def is_protected(self, path: str) -> bool:
        """Whether ``path`` is a protected surface subject to V2 enforcement."""
        if self.protected_paths is None:
            return True
        return any(path.startswith(prefix) for prefix in self.protected_paths)

"""mudraid-middleware — FastAPI/Starlette middleware for MudraID.

Drop-in scope-enforcement for platforms that have registered with the
MudraID trust layer. The full module surface and behaviour land across
tasks M5.2–M5.6 (see ROADMAP.md / BACKLOG.md). This M5.1 scaffold
exposes only the public names so integrator code can import them —
applying ``MudraIDMiddleware`` to an app at this stage raises
``NotImplementedError``.
"""

from mudraid_middleware.exceptions import (
    MudraIDInvalidTokenError,
    MudraIDJwksError,
    MudraIDMiddlewareError,
    MudraIDScopesYamlError,
)
from mudraid_middleware.middleware import MudraIDMiddleware
from mudraid_middleware.v2 import DecideClient, DecideResult, V2Config

__all__ = [
    "MudraIDMiddleware",
    "MudraIDMiddlewareError",
    "MudraIDScopesYamlError",
    "MudraIDJwksError",
    "MudraIDInvalidTokenError",
    # V2 mode (EP-120-US-03)
    "V2Config",
    "DecideClient",
    "DecideResult",
]

# Single source of truth is pyproject.toml (issue #116): read the installed
# package metadata, falling back to the packaged literal for a source checkout
# where the distribution isn't installed. Keep the fallback equal to pyproject's
# version so the two never diverge again.
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("mudraid-middleware")
except PackageNotFoundError:  # source checkout, not pip-installed
    __version__ = "0.2.0"

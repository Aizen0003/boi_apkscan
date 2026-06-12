"""Dynamic analysis sandbox package.

Provides:
  * ``BaseSandbox`` — abstract interface for any sandbox backend.
  * ``SimulatedSandbox`` — offline simulated provider (test / CI / local).
  * ``MobSFSandbox`` — real MobSF Dynamic Analyzer REST client.
  * ``get_sandbox_client`` — factory that selects a backend from settings.
  * ``SandboxError`` — exception for irrecoverable sandbox failures.
"""

from apkscan.dynamic_analysis.base import BaseSandbox, SandboxError
from apkscan.dynamic_analysis.factory import get_sandbox_client
from apkscan.dynamic_analysis.simulator import SimulatedSandbox

__all__ = [
    "BaseSandbox",
    "MobSFSandbox",
    "SandboxError",
    "SimulatedSandbox",
    "get_sandbox_client",
]


def __getattr__(name: str):
    """Lazy-import MobSFSandbox to avoid importing ``requests`` at package load."""
    if name == "MobSFSandbox":
        from apkscan.dynamic_analysis.client import MobSFSandbox

        return MobSFSandbox
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

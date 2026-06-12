"""Sandbox provider factory.

Returns the correct ``BaseSandbox`` implementation based on
``Settings.sandbox_backend``.  The pipeline calls this instead of
constructing a concrete class directly.
"""

from apkscan.config import Settings
from apkscan.dynamic_analysis.base import BaseSandbox


def get_sandbox_client(settings: Settings) -> BaseSandbox:
    """Resolve and return the configured sandbox backend.

    Parameters
    ----------
    settings:
        Application settings — ``sandbox_backend`` selects the provider.

    Returns
    -------
    BaseSandbox
        A ready-to-use sandbox client.

    Raises
    ------
    ValueError
        If ``sandbox_backend`` contains an unrecognised value.
    """
    if settings.sandbox_backend == "simulator":
        from apkscan.dynamic_analysis.simulator import SimulatedSandbox

        return SimulatedSandbox()

    if settings.sandbox_backend == "mobsf":
        from apkscan.dynamic_analysis.client import MobSFSandbox

        return MobSFSandbox(
            api_url=settings.mobsf_url,
            api_key=settings.mobsf_api_key,
            timeout=settings.sandbox_timeout,
        )

    raise ValueError(f"Unknown sandbox_backend: {settings.sandbox_backend!r}")

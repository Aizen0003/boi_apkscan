"""Abstract sandbox interface for dynamic analysis providers.

Every concrete provider (simulated, MobSF, CuckooDroid, …) implements
``BaseSandbox.analyze``.  The pipeline calls the interface, never the
concrete class, so backends can be swapped via ``Settings.sandbox_backend``
without touching the orchestration logic.
"""

from abc import ABC, abstractmethod
from pathlib import Path

from apkscan.schema.features import DynamicFeatures, FeatureSet


class SandboxError(Exception):
    """Raised when a sandbox backend fails irrecoverably."""


class BaseSandbox(ABC):
    """Contract for any dynamic-analysis sandbox backend."""

    @abstractmethod
    def analyze(self, apk_path: Path, features: FeatureSet) -> DynamicFeatures:
        """Run or simulate dynamic analysis for *apk_path*.

        Parameters
        ----------
        apk_path:
            On-disk path to the APK under analysis.
        features:
            The already-extracted static ``FeatureSet``. Implementations may
            use it to tailor instrumentation (e.g. inject Frida hooks for the
            permissions that were actually requested).

        Returns
        -------
        DynamicFeatures
            Populated sandbox observations.  ``captured`` MUST be ``True`` if
            the sandbox ran to completion (even if no events were observed).
        """

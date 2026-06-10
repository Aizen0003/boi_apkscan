"""Integration / export interfaces (T0.19 / FR12).

Clean export of verdict + IOCs for downstream SOC/case-management. Present in the
MVP but off the critical path — the system functions fully without it.
"""

from apkscan.integration.export import build_export

__all__ = ["build_export"]

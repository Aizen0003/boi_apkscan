"""MITRE ATT&CK for Mobile v19.1 mapping (T0.7 / AC5).

Technique IDs are encoded exactly as specified in RESEARCH.md and were
re-verified against attack.mitre.org at implementation time (T1453, T1582,
T1663, T1660, T1544 confirmed present in the Mobile matrix). The technique IDs
are the verified contract; tactic linkage on each technique is informational.
"""

from apkscan.attack.mapping import (
    Behavior,
    BehaviorMatch,
    derive_behaviors,
    technique_for,
    techniques_for_behaviors,
)
from apkscan.attack.techniques import (
    ATTACK_MOBILE_VERSION,
    TACTICS,
    TECHNIQUES,
    Technique,
    get_technique,
)

__all__ = [
    "ATTACK_MOBILE_VERSION",
    "TACTICS",
    "TECHNIQUES",
    "Technique",
    "get_technique",
    "Behavior",
    "BehaviorMatch",
    "derive_behaviors",
    "technique_for",
    "techniques_for_behaviors",
]

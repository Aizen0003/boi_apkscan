"""ATT&CK for Mobile v19.1 technique + tactic catalog.

Only the techniques referenced by the behavior mapping are catalogued. Tactic
linkage uses the well-documented assignments and is informational; the technique
IDs are the verified, load-bearing contract (AC5).
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

ATTACK_MOBILE_VERSION = "19.1"

# The 12 ATT&CK for Mobile tactics (RESEARCH.md).
TACTICS: Dict[str, str] = {
    "TA0027": "Initial Access",
    "TA0041": "Execution",
    "TA0028": "Persistence",
    "TA0029": "Privilege Escalation",
    "TA0030": "Defense Evasion",
    "TA0031": "Credential Access",
    "TA0032": "Discovery",
    "TA0033": "Lateral Movement",
    "TA0035": "Collection",
    "TA0037": "Command and Control",
    "TA0036": "Exfiltration",
    "TA0034": "Impact",
}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def url(self) -> str:
        # Sub-technique URL form: /techniques/T1417/002
        if "." in self.id:
            base, sub = self.id.split(".", 1)
            return f"https://attack.mitre.org/techniques/{base}/{sub}"
        return f"https://attack.mitre.org/techniques/{self.id}"

    def tactic_names(self) -> Tuple[str, ...]:
        return tuple(TACTICS.get(t, t) for t in self.tactics)


def _t(id_: str, name: str, *tactics: str) -> Technique:
    return Technique(id=id_, name=name, tactics=tuple(tactics))


TECHNIQUES: Dict[str, Technique] = {
    t.id: t
    for t in [
        _t("T1417.001", "Keylogging", "TA0035", "TA0031"),
        _t("T1417.002", "GUI Input Capture", "TA0035", "TA0031"),
        _t("T1453", "Abuse Accessibility Features", "TA0031", "TA0035"),
        _t("T1636.004", "Protected User Data: SMS Messages", "TA0035"),
        _t("T1582", "SMS Control", "TA0030"),
        _t("T1513", "Screen Capture", "TA0035"),
        _t("T1512", "Video Capture", "TA0035"),
        _t("T1663", "Remote Access Software", "TA0037"),
        _t("T1628.001", "Hide Artifacts: Suppress Application Icon", "TA0030"),
        _t("T1407", "Download New Code at Runtime", "TA0030"),
        _t("T1544", "Ingress Tool Transfer", "TA0037"),
        _t("T1418", "Software Discovery", "TA0032"),
        _t("T1418.001", "Software Discovery: Security Software Discovery", "TA0032"),
        _t("T1406", "Obfuscated Files or Information", "TA0030"),
        _t("T1406.002", "Obfuscated Files or Information: Software Packing", "TA0030"),
        _t("T1660", "Phishing", "TA0027"),
    ]
}


def get_technique(technique_id: str) -> Optional[Technique]:
    return TECHNIQUES.get(technique_id)

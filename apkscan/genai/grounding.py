"""GenAI grounding / citation enforcement (T0.12 / AC6).

Every material GenAI claim must cite at least one artifact that actually exists
in the extracted features; claims citing non-existent artifacts (the classic
SentinelLABS failure: wrong function names, a mangled C2 endpoint) are withheld
and flagged. Asserted ATT&CK techniques are validated against the v19.1 catalog;
unknown ones are stripped.
"""

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from apkscan.attack.techniques import TECHNIQUES
from apkscan.schema import FeatureSet, GenAIClaim

MATERIAL_CATEGORIES = {"behavior", "ioc", "attack"}


@dataclass
class GroundingResult:
    grounded: List[GenAIClaim]
    withheld: List[GenAIClaim]

    @property
    def failure_rate(self) -> float:
        total = len(self.grounded) + len(self.withheld)
        return round(len(self.withheld) / total, 4) if total else 0.0


def validate_techniques(ids: Sequence[str]) -> Tuple[List[str], List[str]]:
    valid, invalid = [], []
    for tid in ids:
        (valid if tid in TECHNIQUES else invalid).append(tid)
    return valid, invalid


def ground_claims(raw_claims: Sequence[GenAIClaim], features: FeatureSet) -> GroundingResult:
    index: Dict[str, str] = features.artifact_index()
    grounded: List[GenAIClaim] = []
    withheld: List[GenAIClaim] = []

    for claim in raw_claims:
        existing = [ref for ref in claim.artifact_refs if ref in index]
        missing = [ref for ref in claim.artifact_refs if ref not in index]
        valid_tech, invalid_tech = validate_techniques(claim.attack_techniques)

        is_material = claim.category in MATERIAL_CATEGORIES

        if missing or (is_material and not existing):
            notes = []
            if missing:
                notes.append(f"cites non-existent artifact(s): {', '.join(missing)}")
            if is_material and not existing:
                notes.append("material claim with no grounding artifact")
            withheld.append(
                claim.model_copy(
                    update={
                        "grounded": False,
                        "artifact_refs": existing,
                        "attack_techniques": valid_tech,
                        "grounding_note": "; ".join(notes),
                    }
                )
            )
            continue

        note = None
        if invalid_tech:
            note = f"dropped unknown ATT&CK id(s): {', '.join(invalid_tech)}"
        grounded.append(
            claim.model_copy(
                update={
                    "grounded": True,
                    "artifact_refs": existing,
                    "attack_techniques": valid_tech,
                    "grounding_note": note,
                }
            )
        )

    return GroundingResult(grounded=grounded, withheld=withheld)

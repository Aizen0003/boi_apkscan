"""GenAI interpretation contract.

The GenAI layer is *explanatory only*. Its output is grounded against the
extracted features: every material claim must cite artifact ids that exist, or it
is withheld. This model is stored alongside the report (``genai_json``) but never
carries verdict weight (enforced in fusion).
"""

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GenAIClaim(BaseModel):
    text: str
    category: str = "behavior"  # summary | behavior | ioc | recommendation | attack
    artifact_refs: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    grounded: bool = False
    grounding_note: Optional[str] = None


class GenAIInterpretation(BaseModel):
    schema_version: str = "1.0.0"
    created_at: datetime = Field(default_factory=_utcnow)

    generated: bool = False  # whether the LLM actually ran (False => unavailable/degraded)
    model_name: Optional[str] = None

    summary: str = ""
    claims: List[GenAIClaim] = Field(default_factory=list)  # grounded, material claims
    withheld_claims: List[GenAIClaim] = Field(default_factory=list)  # ungrounded -> withheld
    attack_techniques: List[str] = Field(default_factory=list)  # grounded techniques only
    iocs: List[str] = Field(default_factory=list)  # highlighted IOCs (must exist in features)
    recommendations: List[str] = Field(default_factory=list)
    rag_sources: List[str] = Field(default_factory=list)  # retrieved ATT&CK/TI doc ids (provenance)

    # transparency / failure modes
    truncated: bool = False
    chunks_total: int = 0
    chunks_sent: int = 0
    prompt_injection_detected: bool = False
    grounding_failure_rate: float = 0.0
    warnings: List[str] = Field(default_factory=list)

"""Evidence, verdict, and score contracts.

These models make a verdict *auditable*: every contribution to the risk score is
an ``EvidenceItem`` that names its source layer, its weight, the concrete
artifacts it derives from, and any ATT&CK techniques it maps to. The deterministic
rule layer is the primary source of truth; GenAI evidence is explanatory only and
is marked as such so it can never, by construction, move the verdict on its own.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Verdict(str, Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


class Severity(str, Enum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


class EvidenceLayer(str, Enum):
    """Which layer produced an indicator.

    Only RULE, ML, and DYNAMIC may carry decision weight. GENAI is explanatory
    only (``weight`` is forced to 0 by the fusion engine) — this encodes
    'GenAI explains, deterministic + ML decides'.
    """

    RULE = "rule"
    ML = "ml"
    DYNAMIC = "dynamic"
    GENAI = "genai"
    MOBSF = "mobsf"


class EvidenceCategory(str, Enum):
    PERMISSION = "permission"
    PERMISSION_COMBO = "permission_combo"
    QUARK_BEHAVIOR = "quark_behavior"
    YARA = "yara"
    CERTIFICATE = "certificate"
    IOC = "ioc"
    FIREBASE = "firebase"
    DOMAIN = "domain"
    PACKER = "packer"
    ESCALATION = "escalation"
    COMPONENT = "component"
    MOBSF = "mobsf"
    ML_PROBABILITY = "ml_probability"
    GENAI_EXPLANATION = "genai_explanation"
    DYNAMIC_BEHAVIOR = "dynamic_behavior"


class EvidenceItem(BaseModel):
    """One logged contribution to a verdict."""

    id: str
    layer: EvidenceLayer
    category: str
    title: str
    detail: str = ""
    weight: float = 0.0  # signed contribution to the layer's raw score
    confidence: float = 1.0  # 0..1
    artifact_refs: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    metadata: Dict[str, object] = Field(default_factory=dict)


class LayerScore(BaseModel):
    layer: EvidenceLayer
    raw: float
    normalized_0_100: float
    weight_in_fusion: float
    contributed: bool = True
    note: Optional[str] = None


class ScoreResult(BaseModel):
    """The fused, auditable scoring output."""

    schema_version: str = "1.0.0"
    created_at: datetime = Field(default_factory=_utcnow)

    risk_score: float  # 0..100
    verdict: Verdict
    severity: Severity
    confidence: float  # 0..1
    requires_signoff: bool
    operating_mode: str = "balanced"

    layer_scores: List[LayerScore] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    rationale: str = ""

    def rule_evidence(self) -> List[EvidenceItem]:
        return [e for e in self.evidence if e.layer == EvidenceLayer.RULE]

    def decisive_evidence(self) -> List[EvidenceItem]:
        """Evidence that can actually move the verdict (never GenAI)."""

        return [e for e in self.evidence if e.layer != EvidenceLayer.GENAI]

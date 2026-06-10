"""Report document contract (T0.14 / AC6).

A ``ReportDocument`` is the complete, serializable investigation report. The JSON
report is this model verbatim; the PDF renders the same content. It contains the
verdict, confidence, risk score, full evidence log, ATT&CK mapping, IOCs,
recommendations, the grounded GenAI interpretation, and sign-off status.
"""

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from apkscan.schema.evidence import EvidenceItem, Severity, Verdict
from apkscan.schema.features import AnalysisGap, EscalationFlag, IOCSet, SampleMetadata
from apkscan.schema.genai import GenAIInterpretation


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AttackTechniqueRef(BaseModel):
    id: str
    name: str
    tactics: List[str] = Field(default_factory=list)
    url: str = ""
    artifact_refs: List[str] = Field(default_factory=list)


class SignOffBlock(BaseModel):
    required: bool = False
    status: str = "not_required"  # not_required | pending | approved | rejected
    decision: Optional[str] = None
    signed_by: Optional[str] = None
    note: Optional[str] = None
    signed_at: Optional[datetime] = None


class VerdictBlock(BaseModel):
    verdict: Verdict
    severity: Severity
    risk_score: float
    confidence: float
    operating_mode: str
    rationale: str = ""


class ReportDocument(BaseModel):
    schema_version: str = "1.0.0"
    report_id: Optional[str] = None
    generated_at: datetime = Field(default_factory=_utcnow)
    analyst_signoff_required_disclaimer: str = (
        "GenAI content is interpretive only and never determines the verdict; "
        "High/Critical verdicts are not final until an analyst signs off."
    )

    sample: SampleMetadata
    verdict: VerdictBlock
    signoff: SignOffBlock = Field(default_factory=SignOffBlock)

    summary: str = ""
    evidence: List[EvidenceItem] = Field(default_factory=list)
    attack: List[AttackTechniqueRef] = Field(default_factory=list)
    iocs: IOCSet = Field(default_factory=IOCSet)
    recommendations: List[str] = Field(default_factory=list)
    escalation: EscalationFlag = Field(default_factory=EscalationFlag)
    analysis_gaps: List[AnalysisGap] = Field(default_factory=list)
    genai: GenAIInterpretation = Field(default_factory=GenAIInterpretation)

"""Assemble a ReportDocument from features + fused score + GenAI interpretation."""

from typing import Dict, List, Optional

from apkscan.attack.mapping import derive_behaviors
from apkscan.attack.techniques import get_technique
from apkscan.schema import (
    AttackTechniqueRef,
    EscalationFlag,
    FeatureSet,
    GenAIInterpretation,
    ReportDocument,
    ScoreResult,
    SignOffBlock,
    Verdict,
    VerdictBlock,
)


def _attack_refs(features: FeatureSet, score: ScoreResult) -> List[AttackTechniqueRef]:
    behavior_refs: Dict[str, List[str]] = {}
    for match in derive_behaviors(features):
        behavior_refs.setdefault(match.technique_id, [])
        for ref in match.artifact_refs:
            if ref not in behavior_refs[match.technique_id]:
                behavior_refs[match.technique_id].append(ref)

    refs: List[AttackTechniqueRef] = []
    for tid in score.attack_techniques:
        tech = get_technique(tid)
        if tech is None:
            continue
        refs.append(
            AttackTechniqueRef(
                id=tech.id,
                name=tech.name,
                tactics=list(tech.tactic_names()),
                url=tech.url,
                artifact_refs=behavior_refs.get(tid, []),
            )
        )
    return refs


def _recommendations(
    features: FeatureSet, score: ScoreResult, genai: Optional[GenAIInterpretation]
) -> List[str]:
    recs: List[str] = []
    if score.verdict == Verdict.MALICIOUS:
        recs.append("Treat as malicious: blocklist the sample hash and isolate the artifact.")
        if features.iocs.urls or features.iocs.domains or features.iocs.ips:
            recs.append("Block the listed C2/network IOCs at the network edge and on endpoints.")
    elif score.verdict == Verdict.SUSPICIOUS:
        recs.append("Manual analyst review recommended; corroborate with dynamic analysis before action.")
    else:
        recs.append("No malicious indicators above threshold; archive per the retention policy.")

    if score.requires_signoff:
        recs.append("Analyst sign-off is required before this High/Critical verdict is final.")

    if features.escalation.escalate:
        recs.append(
            "Static analysis was partially defeated (packing/encryption/dynamic loading); "
            "route to the isolated dynamic sandbox when enabled and treat the score as a lower bound."
        )
    if features.iocs.firebase_urls:
        recs.append(
            "Report/revoke the referenced Firebase project and rotate any exposed credentials "
            "(Firebase is a common India-campaign C2/exfil sink)."
        )
    sms_related = any(t in score.attack_techniques for t in ("T1636.004", "T1582"))
    if sms_related and score.verdict != Verdict.BENIGN:
        recs.append("Warn affected customers about SMS/OTP interception; consider OTP-channel hardening.")
    if score.verdict == Verdict.MALICIOUS and (features.iocs.firebase_urls or sms_related):
        recs.append("Coordinate regulatory reporting with CERT-In / RBI per obligations.")

    core_gaps = sorted({g.tool for g in features.analysis_gaps if g.severity in ("warning", "error")})
    if core_gaps:
        recs.append(
            f"Note: analyzers unavailable ({', '.join(core_gaps)}); results may understate risk."
        )

    # advisory GenAI recommendations (grounded/interpretive), clearly secondary
    if genai and genai.generated:
        for rec in genai.recommendations:
            tagged = f"[GenAI suggestion] {rec}"
            if rec not in recs and tagged not in recs:
                recs.append(tagged)
    return recs


def _summary(features: FeatureSet, score: ScoreResult, genai: Optional[GenAIInterpretation]) -> str:
    if genai and genai.generated and genai.summary:
        return genai.summary
    categories = sorted({e.category for e in score.evidence if e.weight > 0})
    return (
        f"Deterministic analysis classifies this sample as {score.verdict.value} "
        f"(severity {score.severity.value}, score {score.risk_score:.1f}/100) based on "
        f"{len([e for e in score.evidence if e.weight > 0])} indicator(s) across categories: "
        f"{', '.join(categories) or 'none'}."
    )


def build_report_document(
    features: FeatureSet,
    score: ScoreResult,
    genai: Optional[GenAIInterpretation] = None,
    *,
    signoff: Optional[SignOffBlock] = None,
    report_id: Optional[str] = None,
) -> ReportDocument:
    if signoff is None:
        signoff = SignOffBlock(
            required=score.requires_signoff,
            status="pending" if score.requires_signoff else "not_required",
        )

    return ReportDocument(
        report_id=report_id,
        sample=features.sample,
        verdict=VerdictBlock(
            verdict=score.verdict,
            severity=score.severity,
            risk_score=score.risk_score,
            confidence=score.confidence,
            operating_mode=score.operating_mode,
            rationale=score.rationale,
        ),
        signoff=signoff,
        summary=_summary(features, score, genai),
        evidence=list(score.evidence),
        attack=_attack_refs(features, score),
        iocs=features.iocs,
        recommendations=_recommendations(features, score, genai),
        escalation=features.escalation or EscalationFlag(),
        analysis_gaps=list(features.analysis_gaps),
        genai=genai or GenAIInterpretation(),
    )

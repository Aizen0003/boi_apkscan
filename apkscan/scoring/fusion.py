"""Hybrid scoring fusion (T0.13 / AC4).

Fuses the deterministic rule layer (primary, decides) with the GenAI
interpretation (explanatory only — forced to weight 0) into a final
``ScoreResult``: score, verdict band, severity, confidence, and the complete
evidence log. The ML layer is a declared seam (Phase 1) and is absent here.

Two governance rules are enforced here:
  * **GenAI never decides.** GenAI evidence is recorded with weight 0; the
    verdict derives solely from the rule (and, in Phase 1, ML) score.
  * **No Malicious on permissions alone.** A Malicious verdict driven only by
    permissions — with no corroborating behavior/IOC/cert/escalation evidence and
    no analyzer gaps that would explain the absence — is capped to Suspicious
    (RISKS.md MobSF-false-positive mitigation, TEST_PLAN edge case).
"""

from typing import List, Optional

from apkscan.attack.mapping import derive_behaviors
from apkscan.config import Settings, get_settings
from apkscan.schema import (
    EvidenceCategory,
    EvidenceItem,
    EvidenceLayer,
    FeatureSet,
    GenAIInterpretation,
    LayerScore,
    ScoreResult,
    Severity,
    Verdict,
)
from apkscan.scoring.policy import classify
from apkscan.scoring.rule_engine import RuleResult

_CORROBORATING = {
    EvidenceCategory.QUARK_BEHAVIOR.value,
    EvidenceCategory.YARA.value,
    EvidenceCategory.FIREBASE.value,
    EvidenceCategory.DOMAIN.value,
    EvidenceCategory.CERTIFICATE.value,
    EvidenceCategory.ESCALATION.value,
}
# analyzers whose absence means we *couldn't* corroborate (so don't downgrade)
_CORE_ANALYZERS = {"androguard", "quark", "yara", "mobsf"}


def fuse(
    features: FeatureSet,
    rule_result: RuleResult,
    genai: Optional[GenAIInterpretation] = None,
    *,
    settings: Optional[Settings] = None,
) -> ScoreResult:
    settings = settings or get_settings()
    mode = settings.operating_mode

    rule_score = rule_result.normalized_score
    verdict, severity, requires_signoff = classify(rule_score, mode)

    categories = {e.category for e in rule_result.evidence}
    has_corroboration = bool(categories & _CORROBORATING)
    core_gaps = {g.tool for g in features.analysis_gaps if g.tool in _CORE_ANALYZERS}

    downgraded = False
    if verdict == Verdict.MALICIOUS and not has_corroboration and not core_gaps:
        verdict, severity, requires_signoff = Verdict.SUSPICIOUS, Severity.MODERATE, False
        downgraded = True

    evidence: List[EvidenceItem] = list(rule_result.evidence)
    evidence.extend(_genai_evidence(genai))

    confidence = _confidence(features, rule_result, verdict, downgraded)

    layer_scores = [
        LayerScore(
            layer=EvidenceLayer.RULE,
            raw=rule_result.raw_weight,
            normalized_0_100=rule_score,
            weight_in_fusion=1.0,
            contributed=True,
            note="primary deterministic source of truth",
        ),
        LayerScore(
            layer=EvidenceLayer.GENAI,
            raw=0.0,
            normalized_0_100=0.0,
            weight_in_fusion=0.0,
            contributed=False,
            note="explanatory only — never affects the verdict",
        ),
    ]

    attack_techniques = _attack_techniques(features, rule_result)
    rationale = _rationale(
        rule_score, verdict, severity, rule_result, genai, downgraded, confidence, core_gaps
    )

    return ScoreResult(
        risk_score=rule_score,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        requires_signoff=requires_signoff,
        operating_mode=mode,
        layer_scores=layer_scores,
        evidence=evidence,
        attack_techniques=attack_techniques,
        rationale=rationale,
    )


def _genai_evidence(genai: Optional[GenAIInterpretation]) -> List[EvidenceItem]:
    if not genai or not genai.generated:
        return []
    items: List[EvidenceItem] = []
    for i, claim in enumerate(genai.claims):
        items.append(
            EvidenceItem(
                id=f"genai:claim:{i}",
                layer=EvidenceLayer.GENAI,
                category=EvidenceCategory.GENAI_EXPLANATION.value,
                title="GenAI explanation (grounded; non-deciding)",
                detail=claim.text,
                weight=0.0,  # GenAI never moves the score
                confidence=0.0,
                artifact_refs=list(claim.artifact_refs),
                attack_techniques=list(claim.attack_techniques),
                metadata={"genai": True},
            )
        )
    return items


def _confidence(
    features: FeatureSet, rule_result: RuleResult, verdict: Verdict, downgraded: bool
) -> float:
    categories = {e.category for e in rule_result.evidence}
    corroborate = categories & _CORROBORATING

    conf = 0.5
    conf += 0.08 * len(corroborate)
    if EvidenceCategory.PERMISSION_COMBO.value in categories:
        conf += 0.05

    error_gaps = [g for g in features.analysis_gaps if g.severity == "error"]
    warn_gaps = [g for g in features.analysis_gaps if g.severity == "warning"]
    core_gaps_present = any(g.tool in _CORE_ANALYZERS for g in features.analysis_gaps)
    conf -= 0.10 * min(len(error_gaps), 2)
    conf -= 0.03 * min(len(warn_gaps), 3)
    if features.escalation.escalate:
        conf -= 0.08  # static partially defeated -> more uncertain

    if downgraded:
        conf = min(conf, 0.5)
    # Confidently benign ONLY when nothing fired AND the core analyzers actually
    # ran. If analyzers were unavailable we could not assess the sample, so a
    # "Benign" result must stay low-confidence (fail-safe on uncertainty).
    if verdict == Verdict.BENIGN and not rule_result.evidence and not core_gaps_present:
        conf = max(conf, 0.9)

    return round(max(0.05, min(0.99, conf)), 3)


def _attack_techniques(features: FeatureSet, rule_result: RuleResult) -> List[str]:
    techniques: List[str] = []
    for item in rule_result.evidence:
        for tid in item.attack_techniques:
            if tid not in techniques:
                techniques.append(tid)
    for match in derive_behaviors(features):
        if match.technique_id not in techniques:
            techniques.append(match.technique_id)
    return sorted(techniques)


def _rationale(
    rule_score, verdict, severity, rule_result, genai, downgraded, confidence, core_gaps
) -> str:
    n_ind = len([e for e in rule_result.evidence])
    n_cat = len({e.category for e in rule_result.evidence})
    parts = [
        f"Verdict {verdict.value} (severity {severity.value}) from deterministic rule "
        f"score {rule_score:.1f}/100 over {n_ind} indicators across {n_cat} categories.",
        f"Confidence {confidence:.2f}.",
    ]
    if downgraded:
        parts.append(
            "Capped from Malicious to Suspicious: permission-only signal with no "
            "corroborating behavior/IOC/cert/escalation evidence."
        )
    if core_gaps:
        parts.append(f"Reduced corroboration due to unavailable analyzers: {', '.join(sorted(core_gaps))}.")
    if genai and genai.generated:
        parts.append(
            f"GenAI: explanatory only — {len(genai.claims)} grounded claim(s), "
            f"{len(genai.withheld_claims)} withheld (grounding-failure "
            f"{genai.grounding_failure_rate:.0%}); does not affect the verdict."
        )
    else:
        parts.append("GenAI: not applied (disabled/unavailable); verdict is purely deterministic.")
    return " ".join(parts)

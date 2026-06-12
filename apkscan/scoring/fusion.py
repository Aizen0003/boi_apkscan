"""Hybrid scoring fusion (T0.13 / AC4 + Phase 1 ML + Phase 2 Dynamic).

Fuses the deterministic rule layer (primary, decides) with the ML probability
layer (Phase 1), the dynamic sandbox layer (Phase 2), and the GenAI
interpretation (explanatory only — forced to weight 0) into a final
``ScoreResult``: score, verdict band, severity, confidence, and the complete
evidence log.

Governance rules enforced here:
  * **GenAI never decides.** GenAI evidence is recorded with weight 0; the
    verdict derives solely from the rule + ML + dynamic score.
  * **No Malicious on permissions alone.** A Malicious verdict driven only by
    permissions — with no corroborating behavior/IOC/cert/escalation/dynamic
    evidence and no analyzer gaps that would explain the absence — is capped to
    Suspicious (RISKS.md MobSF-false-positive mitigation, TEST_PLAN edge case).
  * **ML is additive, not overriding.** The ML score is blended with the rule
    score via a configurable weight (default 0.3).
  * **Dynamic evidence boosts, not replaces.** Dynamic findings add score and
    evidence; they never lower an existing score.
"""

import logging
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

logger = logging.getLogger("apkscan.scoring.fusion")

_CORROBORATING = {
    EvidenceCategory.QUARK_BEHAVIOR.value,
    EvidenceCategory.YARA.value,
    EvidenceCategory.FIREBASE.value,
    EvidenceCategory.DOMAIN.value,
    EvidenceCategory.CERTIFICATE.value,
    EvidenceCategory.ESCALATION.value,
    EvidenceCategory.DYNAMIC_BEHAVIOR.value,
}
# analyzers whose absence means we *couldn't* corroborate (so don't downgrade)
_CORE_ANALYZERS = {"androguard", "quark", "yara", "mobsf"}

# ── Anti-evasion: emulator-check API signatures that indicate sandbox awareness ──
_EMULATOR_CHECK_SIGNATURES = (
    "android.os.Build.FINGERPRINT",
    "android.os.Build.MODEL",
    "android.os.Build.MANUFACTURER",
    "android.os.Build.PRODUCT",
    "android.os.Build.BRAND",
    "android.os.Build.HARDWARE",
    "android.telephony.TelephonyManager.getDeviceId",
    "android.telephony.TelephonyManager.getSubscriberId",
    "ro.hardware",
    "ro.kernel.qemu",
    "goldfish",
    "sdk_gphone",
    "generic_x86",
)

# Weight of dynamic evidence in the fused score (additive boost)
_DYNAMIC_BOOST_WEIGHT = 0.15


def _compute_ml(features: FeatureSet, settings: Settings):
    """Return (ml_score_0_100, ml_probability, ml_evidence_item, ml_layer_score) or Nones."""
    if not settings.ml_enabled:
        return None, 0.0, None, None
    try:
        from apkscan.scoring.ml_encoder import FeatureEncoder
        from apkscan.scoring.ml_explainer import MLExplainer
        from apkscan.scoring.ml_trainer import load_classifier, predict_threat_probability

        model = load_classifier(settings.ml_model_path)
        if model is None:
            return None, 0.0, None, None

        encoder = FeatureEncoder()
        vec = encoder.encode(features)
        probability = predict_threat_probability(model, vec)
        ml_score = probability * 100.0

        # SHAP explanation
        explainer = MLExplainer(model, encoder.get_feature_names())
        attrs = explainer.explain_prediction(vec, top_n=5)
        detail = f"Probability: {probability:.1%}. Contributing: {explainer.format_explanation(attrs)}"

        evidence_item = EvidenceItem(
            id="ml:probability",
            layer=EvidenceLayer.ML,
            category=EvidenceCategory.ML_PROBABILITY.value,
            title="ML threat probability",
            detail=detail,
            weight=ml_score,
            confidence=probability,
            artifact_refs=[],
            metadata={"probability": probability, "attributions": attrs},
        )
        layer_score = LayerScore(
            layer=EvidenceLayer.ML,
            raw=probability,
            normalized_0_100=ml_score,
            weight_in_fusion=settings.ml_fusion_weight,
            contributed=True,
            note=f"RF/XGBoost threat probability (weight {settings.ml_fusion_weight})",
        )
        return ml_score, probability, evidence_item, layer_score
    except Exception:
        logger.exception("ML layer failed; falling back to rule-only scoring")
        return None, 0.0, None, None


def _compute_dynamic(features: FeatureSet):
    """Extract dynamic evidence, score boost, evasion notes, and layer score from DynamicFeatures."""
    dyn = features.dynamic
    if dyn is None or not dyn.captured:
        return [], 0.0, False, None, None

    evidence_items: List[EvidenceItem] = []
    boost = 0.0
    evasion_detected = False
    evasion_note: Optional[str] = None

    # SMS interception evidence
    if dyn.sms_events:
        boost += 12.0
        evidence_items.append(EvidenceItem(
            id="dynamic:sms_intercept",
            layer=EvidenceLayer.DYNAMIC,
            category=EvidenceCategory.DYNAMIC_BEHAVIOR.value,
            title="Dynamic SMS interception detected",
            detail=f"Captured {len(dyn.sms_events)} SMS event(s): {'; '.join(dyn.sms_events[:3])}",
            weight=12.0,
            confidence=0.9,
            artifact_refs=[],
            attack_techniques=["T1636.004"],
        ))

    # Network C2 communication evidence
    if dyn.network_endpoints:
        boost += 8.0
        evidence_items.append(EvidenceItem(
            id="dynamic:network_c2",
            layer=EvidenceLayer.DYNAMIC,
            category=EvidenceCategory.DYNAMIC_BEHAVIOR.value,
            title="Dynamic network communication observed",
            detail=f"{len(dyn.network_endpoints)} endpoint(s): {', '.join(dyn.network_endpoints[:5])}",
            weight=8.0,
            confidence=0.85,
            artifact_refs=[],
            attack_techniques=["T1071"],
        ))

    # Code injection / dynamic loading evidence
    classloader_traces = [t for t in dyn.api_trace if "DexClassLoader" in t or "loadClass" in t]
    if classloader_traces:
        boost += 10.0
        evidence_items.append(EvidenceItem(
            id="dynamic:code_injection",
            layer=EvidenceLayer.DYNAMIC,
            category=EvidenceCategory.DYNAMIC_BEHAVIOR.value,
            title="Dynamic code loading observed at runtime",
            detail=f"Class-loader API traces: {'; '.join(classloader_traces[:3])}",
            weight=10.0,
            confidence=0.9,
            artifact_refs=[],
            attack_techniques=["T1407"],
        ))

    # Accessibility abuse evidence
    a11y_traces = [t for t in dyn.api_trace if "AccessibilityService" in t or "AccessibilityNodeInfo" in t]
    if a11y_traces:
        boost += 10.0
        evidence_items.append(EvidenceItem(
            id="dynamic:a11y_abuse",
            layer=EvidenceLayer.DYNAMIC,
            category=EvidenceCategory.DYNAMIC_BEHAVIOR.value,
            title="Accessibility service abuse at runtime",
            detail=f"A11y API traces: {'; '.join(a11y_traces[:3])}",
            weight=10.0,
            confidence=0.9,
            artifact_refs=[],
            attack_techniques=["T1453"],
        ))

    # File operations (e.g. encrypted DEX extraction)
    if dyn.file_ops:
        crypto_ops = [f for f in dyn.file_ops if "DECRYPT" in f or "EXEC" in f]
        if crypto_ops:
            boost += 6.0
            evidence_items.append(EvidenceItem(
                id="dynamic:file_decrypt",
                layer=EvidenceLayer.DYNAMIC,
                category=EvidenceCategory.DYNAMIC_BEHAVIOR.value,
                title="Runtime decryption / code execution from assets",
                detail=f"File operations: {'; '.join(crypto_ops[:3])}",
                weight=6.0,
                confidence=0.85,
                artifact_refs=[],
                attack_techniques=["T1407"],
            ))

    # ── Anti-evasion: detect emulator-awareness or total dormancy ──
    # Check if the API trace contains emulator-check signatures
    emulator_checks = [
        t for t in dyn.api_trace
        if any(sig in t for sig in _EMULATOR_CHECK_SIGNATURES)
    ]
    # Check for total dormancy: static indicators suggest activity but
    # the dynamic trace is suspiciously empty
    has_static_indicators = bool(
        features.permissions
        and len([p for p in features.permissions if p.protection_level == "dangerous"]) >= 3
    )
    is_dormant = (
        has_static_indicators
        and len(dyn.api_trace) == 0
        and len(dyn.network_endpoints) == 0
    )

    if emulator_checks or is_dormant:
        evasion_detected = True
        if emulator_checks:
            evasion_note = (
                f"Anti-emulation: {len(emulator_checks)} emulator-check API(s) detected "
                f"({', '.join(emulator_checks[:3])}). Sample may be sandbox-aware."
            )
        else:
            evasion_note = (
                "Total dormancy: despite static risk indicators, no dynamic API activity "
                "was observed. Sample likely evaded the sandbox environment."
            )
        evidence_items.append(EvidenceItem(
            id="dynamic:evasion",
            layer=EvidenceLayer.DYNAMIC,
            category=EvidenceCategory.DYNAMIC_BEHAVIOR.value,
            title="Anti-emulation / sandbox evasion detected",
            detail=evasion_note,
            weight=5.0,
            confidence=0.6,
            artifact_refs=[],
            attack_techniques=["T1633"],
        ))

    # Build layer score
    dyn_score = min(boost, 100.0)
    layer = LayerScore(
        layer=EvidenceLayer.DYNAMIC,
        raw=boost,
        normalized_0_100=dyn_score,
        weight_in_fusion=_DYNAMIC_BOOST_WEIGHT,
        contributed=bool(evidence_items),
        note=(
            f"Dynamic sandbox: {len(evidence_items)} finding(s), boost {boost:.1f}"
            + (f"; EVASION: {evasion_note}" if evasion_detected else "")
        ),
    )

    return evidence_items, boost, evasion_detected, evasion_note, layer


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

    # ── ML integration (Phase 1) ──
    ml_score, ml_prob, ml_evidence, ml_layer = _compute_ml(features, settings)
    if ml_score is not None:
        w = max(0.0, min(1.0, settings.ml_fusion_weight))
        fused_score = (1.0 - w) * rule_score + w * ml_score
    else:
        fused_score = rule_score

    # ── Dynamic integration (Phase 2) ──
    dyn_evidence, dyn_boost, dyn_evasion, dyn_evasion_note, dyn_layer = _compute_dynamic(features)
    if dyn_boost > 0:
        # Dynamic evidence adds to the fused score (never subtracts)
        fused_score = min(100.0, fused_score + dyn_boost * _DYNAMIC_BOOST_WEIGHT)

    verdict, severity, requires_signoff = classify(fused_score, mode)

    categories = {e.category for e in rule_result.evidence}
    # Include dynamic evidence in corroboration check
    if dyn_evidence:
        categories.update(e.category for e in dyn_evidence)
    has_corroboration = bool(categories & _CORROBORATING)
    core_gaps = {g.tool for g in features.analysis_gaps if g.tool in _CORE_ANALYZERS}

    downgraded = False
    if verdict == Verdict.MALICIOUS and not has_corroboration and not core_gaps:
        verdict, severity, requires_signoff = Verdict.SUSPICIOUS, Severity.MODERATE, False
        downgraded = True

    evidence: List[EvidenceItem] = list(rule_result.evidence)
    if ml_evidence is not None:
        evidence.append(ml_evidence)
    evidence.extend(dyn_evidence)
    evidence.extend(_genai_evidence(genai))

    confidence = _confidence(features, rule_result, verdict, downgraded)
    # Dynamic evasion degrades confidence
    if dyn_evasion:
        confidence = max(0.05, confidence - 0.15)
        confidence = round(confidence, 3)

    # ── layer scores ──
    rule_fusion_weight = 1.0 if ml_score is None else (1.0 - settings.ml_fusion_weight)
    layer_scores = [
        LayerScore(
            layer=EvidenceLayer.RULE,
            raw=rule_result.raw_weight,
            normalized_0_100=rule_score,
            weight_in_fusion=rule_fusion_weight,
            contributed=True,
            note="primary deterministic source of truth",
        ),
    ]
    if ml_layer is not None:
        layer_scores.append(ml_layer)
    else:
        layer_scores.append(
            LayerScore(
                layer=EvidenceLayer.ML,
                raw=0.0,
                normalized_0_100=0.0,
                weight_in_fusion=0.0,
                contributed=False,
                note="ML layer disabled or model not loaded",
            )
        )
    # Dynamic layer
    if dyn_layer is not None:
        layer_scores.append(dyn_layer)
    else:
        layer_scores.append(
            LayerScore(
                layer=EvidenceLayer.DYNAMIC,
                raw=0.0,
                normalized_0_100=0.0,
                weight_in_fusion=0.0,
                contributed=False,
                note="Dynamic sandbox not triggered or not captured",
            )
        )
    layer_scores.append(
        LayerScore(
            layer=EvidenceLayer.GENAI,
            raw=0.0,
            normalized_0_100=0.0,
            weight_in_fusion=0.0,
            contributed=False,
            note="explanatory only — never affects the verdict",
        ),
    )

    attack_techniques = _attack_techniques(features, rule_result)
    rationale = _rationale(
        fused_score, verdict, severity, rule_result, genai, downgraded, confidence, core_gaps,
        ml_score=ml_score, ml_prob=ml_prob,
        dyn_boost=dyn_boost, dyn_evasion=dyn_evasion, dyn_evasion_note=dyn_evasion_note,
    )

    return ScoreResult(
        risk_score=fused_score,
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
    rule_score, verdict, severity, rule_result, genai, downgraded, confidence, core_gaps,
    *, ml_score=None, ml_prob=None,
    dyn_boost=0.0, dyn_evasion=False, dyn_evasion_note=None,
) -> str:
    n_ind = len([e for e in rule_result.evidence])
    n_cat = len({e.category for e in rule_result.evidence})
    parts = [
        f"Verdict {verdict.value} (severity {severity.value}) from deterministic rule "
        f"score {rule_score:.1f}/100 over {n_ind} indicators across {n_cat} categories.",
        f"Confidence {confidence:.2f}.",
    ]
    if ml_score is not None and ml_prob is not None:
        parts.append(
            f"ML layer: threat probability {ml_prob:.1%} "
            f"(score {ml_score:.1f}/100, blended into fused score)."
        )
    else:
        parts.append("ML layer: disabled or model not loaded.")
    if dyn_boost > 0:
        parts.append(f"Dynamic layer: boost +{dyn_boost:.1f} from sandbox evidence.")
    else:
        parts.append("Dynamic layer: not triggered or no findings.")
    if dyn_evasion and dyn_evasion_note:
        parts.append(f"EVASION ALERT: {dyn_evasion_note}")
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


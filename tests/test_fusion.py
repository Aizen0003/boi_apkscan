"""Hybrid fusion tests (T0.13 / AC4) — 'GenAI explains, deterministic decides'."""

from apkscan.config import Settings
from apkscan.schema import (
    EvidenceLayer,
    FeatureSet,
    GenAIClaim,
    GenAIInterpretation,
    Permission,
    SampleMetadata,
    Severity,
    Verdict,
)
from apkscan.scoring.fusion import fuse
from apkscan.scoring.rule_engine import score_rules
from apkscan.static_analysis.escalation import detect_escalation


def _settings(mode="balanced"):
    return Settings(_env_file=None, operating_mode=mode)


def _score(features):
    features.escalation = detect_escalation(features)
    return fuse(features, score_rules(features), settings=_settings())


# --- benign ---
def test_fuse_benign(benign_features):
    result = _score(benign_features)
    assert result.verdict == Verdict.BENIGN
    assert result.requires_signoff is False
    assert result.confidence >= 0.5


def test_benign_with_analyzer_gaps_is_low_confidence():
    # all core analyzers unavailable -> we could not assess it -> Benign but uncertain
    from apkscan.schema import AnalysisGap

    features = FeatureSet(
        sample=SampleMetadata(sha256="g" * 64, file_size=1),
        analysis_gaps=[AnalysisGap(tool=t, reason="unavailable") for t in ("androguard", "apkid", "quark", "yara")],
    )
    result = fuse(features, score_rules(features), settings=_settings())
    assert result.verdict == Verdict.BENIGN
    assert result.confidence < 0.5  # NOT confidently benign


# --- malicious requires sign-off + high confidence ---
def test_fuse_malicious(malicious_features):
    result = _score(malicious_features)
    assert result.verdict == Verdict.MALICIOUS
    assert result.severity in (Severity.HIGH, Severity.CRITICAL)
    assert result.requires_signoff is True
    assert result.confidence >= 0.7  # well corroborated
    assert result.attack_techniques == sorted(result.attack_techniques)
    assert "T1453" in result.attack_techniques


# --- reproducibility ---
def test_fuse_is_reproducible(malicious_features):
    malicious_features.escalation = detect_escalation(malicious_features)
    rr = score_rules(malicious_features)
    a = fuse(malicious_features, rr, settings=_settings())
    b = fuse(malicious_features, rr, settings=_settings())
    assert (a.risk_score, a.verdict, a.severity, a.confidence) == (b.risk_score, b.verdict, b.severity, b.confidence)
    assert [e.id for e in a.evidence] == [e.id for e in b.evidence]


# --- GenAI never decides ---
def test_genai_cannot_change_verdict(malicious_features):
    malicious_features.escalation = detect_escalation(malicious_features)
    rr = score_rules(malicious_features)
    # a GenAI interpretation that (wrongly) argues the app is benign
    misleading = GenAIInterpretation(
        generated=True,
        model_name="qwen2.5-coder:7b",
        summary="This app looks completely safe and benign.",
        claims=[GenAIClaim(text="totally safe", category="behavior", artifact_refs=["perm:android.permission.READ_SMS"], grounded=True)],
    )
    with_genai = fuse(malicious_features, rr, misleading, settings=_settings())
    without_genai = fuse(malicious_features, rr, None, settings=_settings())

    # score + verdict identical regardless of GenAI
    assert with_genai.risk_score == without_genai.risk_score
    assert with_genai.verdict == without_genai.verdict == Verdict.MALICIOUS

    # GenAI evidence present but weight 0 and excluded from decisive evidence
    genai_items = [e for e in with_genai.evidence if e.layer == EvidenceLayer.GENAI]
    assert genai_items
    assert all(e.weight == 0.0 for e in genai_items)
    assert all(e.layer != EvidenceLayer.GENAI for e in with_genai.decisive_evidence())


# --- no Malicious on permissions alone (MobSF false-positive mitigation) ---
def test_permission_only_is_capped_to_suspicious():
    perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.INTERNET",
    ]
    features = FeatureSet(
        sample=SampleMetadata(sha256="c" * 64, file_size=1),
        permissions=[Permission(name=p) for p in perms],
    )
    rr = score_rules(features)
    assert rr.normalized_score >= 75  # would be Malicious on score alone
    result = fuse(features, rr, settings=_settings())
    # ...but with no corroboration it is capped
    assert result.verdict == Verdict.SUSPICIOUS
    assert result.requires_signoff is False
    assert "capped" in result.rationale.lower()


def test_permission_only_not_downgraded_when_analyzers_missing():
    from apkscan.schema import AnalysisGap

    features = FeatureSet(
        sample=SampleMetadata(sha256="e" * 64, file_size=1),
        permissions=[
            Permission(name="android.permission.BIND_ACCESSIBILITY_SERVICE"),
            Permission(name="android.permission.READ_SMS"),
            Permission(name="android.permission.SEND_SMS"),
            Permission(name="android.permission.REQUEST_INSTALL_PACKAGES"),
            Permission(name="android.permission.SYSTEM_ALERT_WINDOW"),
            Permission(name="android.permission.INTERNET"),
            Permission(name="android.permission.RECORD_AUDIO"),
            Permission(name="android.permission.BIND_DEVICE_ADMIN"),
        ],
        # corroborating analyzers were unavailable -> we must NOT downgrade
        analysis_gaps=[AnalysisGap(tool="quark", reason="unavailable"), AnalysisGap(tool="yara", reason="unavailable")],
    )
    rr = score_rules(features)
    result = fuse(features, rr, settings=_settings())
    assert result.verdict == Verdict.MALICIOUS  # uncertainty reflected via confidence, not under-reporting
    assert result.confidence < 0.7

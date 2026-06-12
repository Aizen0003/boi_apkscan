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


# --- ML fusion integration ---
def test_ml_fusion_disabled_by_default(benign_features):
    # ML is disabled by default, so score should equal rule score
    rr = score_rules(benign_features)
    result = fuse(benign_features, rr, settings=_settings())
    assert result.risk_score == rr.normalized_score
    # No ML layer score or evidence should have contributed
    ml_layer = next(l for l in result.layer_scores if l.layer == EvidenceLayer.ML)
    assert ml_layer.contributed is False


def test_ml_fusion_active_and_blended(benign_features, tmp_path):
    from unittest.mock import patch
    
    # Enable ML in settings
    settings = Settings(
        _env_file=None,
        ml_enabled=True,
        ml_model_path=str(tmp_path / "dummy_model.pkl"),
        ml_fusion_weight=0.4
    )
    
    # Mock model loading and prediction
    with patch("apkscan.scoring.ml_trainer.load_classifier") as mock_load, \
         patch("apkscan.scoring.ml_trainer.predict_threat_probability") as mock_predict, \
         patch("apkscan.scoring.ml_explainer.MLExplainer") as mock_explainer_cls:
        
        mock_load.return_value = "dummy_model_object"
        mock_predict.return_value = 0.8  # ML score 80.0
        
        # Mock SHAP Explainer
        mock_explainer = mock_explainer_cls.return_value
        mock_explainer.explain_prediction.return_value = {"perm:READ_SMS": 0.2, "api:SmsManager": 0.15}
        mock_explainer.format_explanation.return_value = "READ_SMS (+0.20), SmsManager (+0.15)"
        
        rr = score_rules(benign_features) # rule score is low (usually ~5.4)
        result = fuse(benign_features, rr, settings=settings)
        
        # blended score = 0.6 * rule_score + 0.4 * 80.0
        expected = 0.6 * rr.normalized_score + 0.4 * 80.0
        assert abs(result.risk_score - expected) < 1e-9
        
        # Verify evidence item is added
        ml_ev = next(e for e in result.evidence if e.layer == EvidenceLayer.ML)
        assert ml_ev.weight == 80.0
        assert ml_ev.confidence == 0.8
        assert "READ_SMS" in ml_ev.detail
        
        # Verify layer score is marked contributed
        ml_layer = next(l for l in result.layer_scores if l.layer == EvidenceLayer.ML)
        assert ml_layer.contributed is True
        assert ml_layer.weight_in_fusion == 0.4
        
        rule_layer = next(l for l in result.layer_scores if l.layer == EvidenceLayer.RULE)
        assert rule_layer.weight_in_fusion == 0.6


def test_ml_fusion_graceful_fallback_when_model_missing(benign_features, tmp_path):
    from unittest.mock import patch
    
    settings = Settings(
        _env_file=None,
        ml_enabled=True,
        ml_model_path=str(tmp_path / "nonexistent.pkl"),
        ml_fusion_weight=0.3
    )
    
    # load_classifier returns None when file is missing
    with patch("apkscan.scoring.ml_trainer.load_classifier", return_value=None):
        rr = score_rules(benign_features)
        result = fuse(benign_features, rr, settings=settings)
        # Fall back to rule score
        assert result.risk_score == rr.normalized_score
        
        ml_layer = next(l for l in result.layer_scores if l.layer == EvidenceLayer.ML)
        assert ml_layer.contributed is False
        assert "disabled or model not loaded" in ml_layer.note


def test_ml_fusion_respects_permissions_only_safety_cap(tmp_path):
    from unittest.mock import patch
    
    # Enable ML
    settings = Settings(
        _env_file=None,
        ml_enabled=True,
        ml_model_path=str(tmp_path / "dummy_model.pkl"),
        ml_fusion_weight=0.5
    )
    
    # Setup permissions-only features (no behavior or other corroborators)
    perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ]
    features = FeatureSet(
        sample=SampleMetadata(sha256="c" * 64, file_size=1),
        permissions=[Permission(name=p) for p in perms],
    )
    
    with patch("apkscan.scoring.ml_trainer.load_classifier", return_value="model"), \
         patch("apkscan.scoring.ml_trainer.predict_threat_probability", return_value=0.9), \
         patch("apkscan.scoring.ml_explainer.MLExplainer") as mock_exp:
        
        mock_exp.return_value.explain_prediction.return_value = {}
        mock_exp.return_value.format_explanation.return_value = ""
        
        rr = score_rules(features)
        result = fuse(features, rr, settings=settings)
        
        # The fused score should be high enough to trigger Malicious, but
        # because we only have permissions, it should be capped to Suspicious
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.requires_signoff is False
        assert "capped" in result.rationale.lower()



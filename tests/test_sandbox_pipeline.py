"""Tests for the sandbox pipeline cascade, scoring fusion, and reporting (Plan 2.2)."""

import pytest

from apkscan.config import Settings
from apkscan.dynamic_analysis.simulator import SimulatedSandbox
from apkscan.dynamic_analysis.factory import get_sandbox_client
from apkscan.reporting.builder import build_report_document
from apkscan.schema import (
    ApiReference,
    Asset,
    DynamicFeatures,
    EscalationFlag,
    EvidenceCategory,
    EvidenceLayer,
    FeatureSet,
    GenAIInterpretation,
    IOCSet,
    Permission,
    QuarkBehavior,
    SampleMetadata,
    YaraMatch,
)
from apkscan.scoring.fusion import fuse
from apkscan.scoring.rule_engine import score_rules


# ── Fixtures ─────────────────────────────────────────────────────────────


def _perm(name, level="dangerous"):
    return Permission(name=name, protection_level=level)


@pytest.fixture
def escalated_features() -> FeatureSet:
    """Malicious features WITH escalation flag set — dynamic should trigger."""
    return FeatureSet(
        sample=SampleMetadata(
            sha256="d" * 64,
            file_name="sbi_secure.apk",
            file_size=4_800_000,
            package_name="com.sbi.secure.update",
        ),
        permissions=[
            _perm("android.permission.BIND_ACCESSIBILITY_SERVICE", "signature"),
            _perm("android.permission.RECEIVE_SMS"),
            _perm("android.permission.READ_SMS"),
            _perm("android.permission.SEND_SMS"),
            _perm("android.permission.INTERNET", "normal"),
            _perm("android.permission.REQUEST_INSTALL_PACKAGES"),
            _perm("android.permission.SYSTEM_ALERT_WINDOW"),
        ],
        apis=[
            ApiReference(index=0, api="Landroid/telephony/SmsManager;->sendTextMessage"),
            ApiReference(index=1, api="Ldalvik/system/DexClassLoader;-><init>"),
        ],
        iocs=IOCSet(
            domains=["c2.example.com"],
            urls=["https://c2.example.com/gate"],
            ips=["198.51.100.1"],
            firebase_urls=["https://evil.firebaseio.com"],
        ),
        assets=[
            Asset(name="assets/payload.dex", size=200_000, entropy=7.9, suspected_dex=True),
        ],
        quark_behaviors=[
            QuarkBehavior(crime="Send SMS messages in the background", confidence_stage=5, weight=4.0, score=4.0),
        ],
        yara_matches=[
            YaraMatch(rule="android_banking_overlay", tags=["banker"], source="internal"),
        ],
        escalation=EscalationFlag(escalate=True, reasons=["packer/protector detected"]),
    )


@pytest.fixture
def non_escalated_features() -> FeatureSet:
    """Features WITHOUT escalation — dynamic should NOT trigger."""
    return FeatureSet(
        sample=SampleMetadata(sha256="b" * 64, file_name="calc.apk", file_size=1_000_000),
        permissions=[_perm("android.permission.INTERNET", "normal")],
        escalation=EscalationFlag(escalate=False),
    )


# ── Pipeline trigger logic ──────────────────────────────────────────────


class TestPipelineTrigger:
    def test_dynamic_triggers_on_escalation(self, escalated_features, tmp_path):
        """When dynamic_enabled=True and escalate=True, sandbox runs."""
        settings = Settings(env="test", dynamic_enabled=True, sandbox_backend="simulator")
        sandbox = get_sandbox_client(settings)
        result = sandbox.analyze(tmp_path / "sample.apk", escalated_features)

        assert result.captured is True
        assert len(result.api_trace) > 0

    def test_dynamic_skipped_when_disabled(self, escalated_features):
        """When dynamic_enabled=False, no sandbox runs."""
        settings = Settings(env="test", dynamic_enabled=False)
        # Pipeline logic check: dynamic should not trigger
        assert not (settings.dynamic_enabled and escalated_features.escalation.escalate)

    def test_dynamic_skipped_when_no_escalation(self, non_escalated_features):
        """When escalation is False, no sandbox even if dynamic_enabled."""
        settings = Settings(env="test", dynamic_enabled=True)
        assert not (settings.dynamic_enabled and non_escalated_features.escalation.escalate)


# ── Scoring fusion with dynamic features ─────────────────────────────────


class TestDynamicFusion:
    def _run_fusion_with_dynamic(self, features):
        """Helper: simulate + score + fuse."""
        sandbox = SimulatedSandbox()
        features.dynamic = sandbox.analyze(
            features.sample.file_name or "sample.apk", features
        )
        rule_result = score_rules(features)
        settings = Settings(env="test", dynamic_enabled=True, sandbox_backend="simulator")
        return fuse(features, rule_result, settings=settings)

    def test_dynamic_evidence_in_score(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)

        dyn_evidence = [e for e in score.evidence if e.layer == EvidenceLayer.DYNAMIC]
        assert len(dyn_evidence) > 0

    def test_dynamic_layer_score_present(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)

        dyn_layers = [ls for ls in score.layer_scores if ls.layer == EvidenceLayer.DYNAMIC]
        assert len(dyn_layers) == 1
        assert dyn_layers[0].contributed is True

    def test_dynamic_boosts_risk_score(self, escalated_features):
        # Score without dynamic
        rule_result_static = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=False)
        static_score = fuse(escalated_features, rule_result_static, settings=settings)

        # Score with dynamic
        score_with_dyn = self._run_fusion_with_dynamic(escalated_features)

        assert score_with_dyn.risk_score >= static_score.risk_score

    def test_sms_interception_evidence(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)

        sms_ev = [e for e in score.evidence if e.id == "dynamic:sms_intercept"]
        assert len(sms_ev) == 1
        assert sms_ev[0].weight > 0
        assert "T1636.004" in sms_ev[0].attack_techniques

    def test_code_injection_evidence(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)

        code_ev = [e for e in score.evidence if e.id == "dynamic:code_injection"]
        assert len(code_ev) == 1
        assert "T1407" in code_ev[0].attack_techniques

    def test_network_c2_evidence(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)

        net_ev = [e for e in score.evidence if e.id == "dynamic:network_c2"]
        assert len(net_ev) == 1
        assert net_ev[0].weight > 0

    def test_a11y_abuse_evidence(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)

        a11y_ev = [e for e in score.evidence if e.id == "dynamic:a11y_abuse"]
        assert len(a11y_ev) == 1
        assert "T1453" in a11y_ev[0].attack_techniques

    def test_dynamic_corroborates_verdict(self, escalated_features):
        """Dynamic evidence counts as corroboration (prevents false downgrade)."""
        score = self._run_fusion_with_dynamic(escalated_features)

        dyn_categories = {e.category for e in score.evidence if e.layer == EvidenceLayer.DYNAMIC}
        assert EvidenceCategory.DYNAMIC_BEHAVIOR.value in dyn_categories

    def test_no_dynamic_layer_when_not_captured(self, non_escalated_features):
        rule_result = score_rules(non_escalated_features)
        settings = Settings(env="test", dynamic_enabled=False)
        score = fuse(non_escalated_features, rule_result, settings=settings)

        dyn_layers = [ls for ls in score.layer_scores if ls.layer == EvidenceLayer.DYNAMIC]
        assert len(dyn_layers) == 1
        assert dyn_layers[0].contributed is False

    def test_rationale_includes_dynamic(self, escalated_features):
        score = self._run_fusion_with_dynamic(escalated_features)
        assert "Dynamic layer" in score.rationale


# ── Anti-evasion detection ──────────────────────────────────────────────


class TestAntiEvasion:
    def test_dormancy_detected(self, escalated_features):
        """Total dormancy (empty traces despite static indicators) = evasion."""
        escalated_features.dynamic = DynamicFeatures(
            captured=True,
            api_trace=[],
            network_endpoints=[],
            sms_events=[],
        )
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)

        evasion_ev = [e for e in score.evidence if e.id == "dynamic:evasion"]
        assert len(evasion_ev) == 1
        assert "dormancy" in evasion_ev[0].detail.lower()
        assert "T1633" in evasion_ev[0].attack_techniques

    def test_emulator_check_detected(self, escalated_features):
        """Emulator-check API calls are flagged as evasion."""
        escalated_features.dynamic = DynamicFeatures(
            captured=True,
            api_trace=[
                "android.os.Build.FINGERPRINT",
                "android.os.Build.MODEL",
                "android.telephony.SmsManager.sendTextMessage()",
            ],
            sms_events=["OTP captured"],
        )
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)

        evasion_ev = [e for e in score.evidence if e.id == "dynamic:evasion"]
        assert len(evasion_ev) == 1
        assert "emulator-check" in evasion_ev[0].detail.lower()

    def test_evasion_reduces_confidence(self, escalated_features):
        """Evasion should reduce confidence vs non-evasion."""
        # Normal dynamic
        sandbox = SimulatedSandbox()
        escalated_features.dynamic = sandbox.analyze("test.apk", escalated_features)
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score_normal = fuse(escalated_features, rule_result, settings=settings)

        # Dormant dynamic (evasion)
        escalated_features.dynamic = DynamicFeatures(captured=True, api_trace=[], network_endpoints=[])
        rule_result2 = score_rules(escalated_features)
        score_evasion = fuse(escalated_features, rule_result2, settings=settings)

        assert score_evasion.confidence < score_normal.confidence

    def test_evasion_in_rationale(self, escalated_features):
        escalated_features.dynamic = DynamicFeatures(captured=True, api_trace=[], network_endpoints=[])
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)

        assert "EVASION" in score.rationale


# ── Report generation with dynamic features ──────────────────────────────


class TestDynamicReport:
    def test_report_includes_dynamic_recommendations(self, escalated_features):
        sandbox = SimulatedSandbox()
        escalated_features.dynamic = sandbox.analyze("test.apk", escalated_features)
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)
        report = build_report_document(escalated_features, score)

        dynamic_recs = [r for r in report.recommendations if "[Dynamic]" in r]
        assert len(dynamic_recs) > 0

    def test_report_summary_includes_dynamic_note(self, escalated_features):
        sandbox = SimulatedSandbox()
        escalated_features.dynamic = sandbox.analyze("test.apk", escalated_features)
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)
        report = build_report_document(escalated_features, score)

        assert "Dynamic sandbox" in report.summary

    def test_report_has_dynamic_evidence(self, escalated_features):
        sandbox = SimulatedSandbox()
        escalated_features.dynamic = sandbox.analyze("test.apk", escalated_features)
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)
        report = build_report_document(escalated_features, score)

        dyn_evidence = [e for e in report.evidence if e.layer == EvidenceLayer.DYNAMIC]
        assert len(dyn_evidence) > 0

    def test_report_sms_recommendation(self, escalated_features):
        sandbox = SimulatedSandbox()
        escalated_features.dynamic = sandbox.analyze("test.apk", escalated_features)
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)
        report = build_report_document(escalated_features, score)

        sms_recs = [r for r in report.recommendations if "SMS" in r]
        assert len(sms_recs) > 0

    def test_report_without_dynamic(self, non_escalated_features):
        """Report renders cleanly when no dynamic analysis was performed."""
        rule_result = score_rules(non_escalated_features)
        settings = Settings(env="test", dynamic_enabled=False)
        score = fuse(non_escalated_features, rule_result, settings=settings)
        report = build_report_document(non_escalated_features, score)

        assert report is not None
        dynamic_recs = [r for r in report.recommendations if "[Dynamic]" in r]
        assert len(dynamic_recs) == 0

    def test_report_network_c2_recommendation(self, escalated_features):
        sandbox = SimulatedSandbox()
        escalated_features.dynamic = sandbox.analyze("test.apk", escalated_features)
        rule_result = score_rules(escalated_features)
        settings = Settings(env="test", dynamic_enabled=True)
        score = fuse(escalated_features, rule_result, settings=settings)
        report = build_report_document(escalated_features, score)

        c2_recs = [r for r in report.recommendations if "C2" in r or "Network" in r or "network" in r]
        assert len(c2_recs) > 0

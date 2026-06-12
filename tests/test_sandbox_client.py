"""Tests for the dynamic sandbox client, simulator, and factory (Plan 2.1)."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import json

import pytest

from apkscan.config import Settings
from apkscan.dynamic_analysis.base import BaseSandbox, SandboxError
from apkscan.dynamic_analysis.simulator import SimulatedSandbox
from apkscan.dynamic_analysis.factory import get_sandbox_client
from apkscan.schema import (
    ApiReference,
    Asset,
    DynamicFeatures,
    EscalationFlag,
    FeatureSet,
    IOCSet,
    Permission,
    SampleMetadata,
)


# ── Fixtures ─────────────────────────────────────────────────────────────


def _perm(name, level="dangerous"):
    return Permission(name=name, protection_level=level)


@pytest.fixture
def high_risk_features() -> FeatureSet:
    """A sample with high-risk permissions that should trigger simulation."""
    return FeatureSet(
        sample=SampleMetadata(sha256="a" * 64, file_name="evil.apk", file_size=5_000_000),
        permissions=[
            _perm("android.permission.READ_SMS"),
            _perm("android.permission.RECEIVE_SMS"),
            _perm("android.permission.SEND_SMS"),
            _perm("android.permission.BIND_ACCESSIBILITY_SERVICE", "signature"),
            _perm("android.permission.SYSTEM_ALERT_WINDOW"),
            _perm("android.permission.REQUEST_INSTALL_PACKAGES"),
            _perm("android.permission.RECORD_AUDIO"),
        ],
        apis=[
            ApiReference(index=0, api="Ldalvik/system/DexClassLoader;-><init>"),
        ],
        iocs=IOCSet(
            urls=["https://c2.example.com/gate"],
            ips=["198.51.100.1"],
        ),
        assets=[
            Asset(name="assets/payload.dex", size=200_000, entropy=7.9, suspected_encrypted=True, suspected_dex=True),
        ],
        escalation=EscalationFlag(escalate=True, reasons=["packer detected"]),
    )


@pytest.fixture
def benign_only_features() -> FeatureSet:
    """A benign sample with no high-risk permissions."""
    return FeatureSet(
        sample=SampleMetadata(sha256="b" * 64, file_name="calc.apk", file_size=1_000_000),
        permissions=[
            _perm("android.permission.INTERNET", "normal"),
        ],
    )


@pytest.fixture
def fake_apk(tmp_path) -> Path:
    p = tmp_path / "sample.apk"
    p.write_bytes(b"PK\x03\x04" + b"fake" * 100)
    return p


# ── BaseSandbox contract ────────────────────────────────────────────────


class TestBaseSandbox:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseSandbox()

    def test_subclass_must_implement_analyze(self):
        class Incomplete(BaseSandbox):
            pass

        with pytest.raises(TypeError):
            Incomplete()


# ── SimulatedSandbox ────────────────────────────────────────────────────


class TestSimulatedSandbox:
    def test_high_risk_produces_traces(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        assert isinstance(result, DynamicFeatures)
        assert result.captured is True
        assert len(result.api_trace) > 0
        assert len(result.sms_events) > 0
        assert len(result.network_endpoints) > 0
        assert "Simulated" in result.notes

    def test_sms_permissions_produce_sms_events(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        sms_traces = [t for t in result.api_trace if "SmsManager" in t]
        assert len(sms_traces) > 0
        assert any("SMS" in e for e in result.sms_events)

    def test_accessibility_traces(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        a11y_traces = [t for t in result.api_trace if "AccessibilityService" in t]
        assert len(a11y_traces) > 0

    def test_classloader_traces(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        loader_traces = [t for t in result.api_trace if "DexClassLoader" in t]
        assert len(loader_traces) > 0

    def test_network_includes_static_iocs(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        assert "https://c2.example.com/gate" in result.network_endpoints

    def test_file_ops_for_encrypted_assets(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        assert len(result.file_ops) > 0
        assert any("EXEC" in op or "DECRYPT" in op for op in result.file_ops)

    def test_pcap_summary_present(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        assert result.pcap_summary
        assert "total_packets" in result.pcap_summary

    def test_benign_produces_empty_dynamic(self, fake_apk, benign_only_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, benign_only_features)

        assert result.captured is True
        assert result.api_trace == []
        assert result.sms_events == []
        assert result.network_endpoints == []
        assert result.file_ops == []

    def test_overlay_permission(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        overlay_traces = [t for t in result.api_trace if "WindowManager" in t]
        assert len(overlay_traces) > 0

    def test_audio_permission(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        audio_traces = [t for t in result.api_trace if "MediaRecorder" in t or "AudioRecord" in t]
        assert len(audio_traces) > 0

    def test_no_duplicates_in_traces(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        assert len(result.api_trace) == len(set(result.api_trace))
        assert len(result.network_endpoints) == len(set(result.network_endpoints))

    def test_install_package_traces(self, fake_apk, high_risk_features):
        sandbox = SimulatedSandbox()
        result = sandbox.analyze(fake_apk, high_risk_features)

        install_traces = [t for t in result.api_trace if "INSTALL_PACKAGE" in t or "PackageInstaller" in t]
        assert len(install_traces) > 0


# ── Factory ──────────────────────────────────────────────────────────────


class TestFactory:
    def test_default_returns_simulator(self):
        settings = Settings(
            env="test",
            dynamic_enabled=True,
            sandbox_backend="simulator",
        )
        client = get_sandbox_client(settings)
        assert isinstance(client, SimulatedSandbox)

    def test_mobsf_returns_mobsf_client(self):
        settings = Settings(
            env="test",
            dynamic_enabled=True,
            sandbox_backend="mobsf",
            mobsf_api_key="test-key-123",
        )
        client = get_sandbox_client(settings)
        from apkscan.dynamic_analysis.client import MobSFSandbox
        assert isinstance(client, MobSFSandbox)

    def test_unknown_backend_raises(self):
        settings = Settings(
            env="test",
            dynamic_enabled=True,
        )
        # Force an invalid backend (pydantic will validate at construction;
        # we bypass by setting after construction)
        object.__setattr__(settings, "sandbox_backend", "unknown")
        with pytest.raises(ValueError, match="Unknown sandbox_backend"):
            get_sandbox_client(settings)


# ── MobSFSandbox (mocked HTTP) ──────────────────────────────────────────


class TestMobSFSandbox:
    def _make_client(self):
        from apkscan.dynamic_analysis.client import MobSFSandbox
        return MobSFSandbox(api_url="http://localhost:8000", api_key="test-key", timeout=10)

    def test_analyze_full_flow(self, fake_apk, high_risk_features):
        client = self._make_client()

        mock_report = {
            "api_monitor": ["SmsManager.sendTextMessage()", "DexClassLoader.loadClass()"],
            "frida_logs": ["Cipher.doFinal()"],
            "domains": [{"domain": "c2.example.com"}],
            "urls": ["https://c2.example.com/gate"],
            "sms": ["Intercepted OTP: 123456"],
            "file_analysis": ["/data/payload.dex"],
            "pcap": "/tmp/capture.pcap",
            "tls_tests": {"tls1.2": "pass"},
        }

        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"hash": "aaa", "status": "ok"}
        mock_response.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_response

        # Override the report response for the last call
        responses = [
            mock_response,  # upload
            mock_response,  # start
        ] + [mock_response] * 6  # 6 frida hooks
        report_response = MagicMock()
        report_response.json.return_value = mock_report
        report_response.raise_for_status = MagicMock()
        responses.append(mock_response)  # stop
        responses.append(report_response)  # report_json

        mock_requests.post.side_effect = responses

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = client.analyze(fake_apk, high_risk_features)

        assert isinstance(result, DynamicFeatures)
        assert result.captured is True
        assert "SmsManager.sendTextMessage()" in result.api_trace
        assert "c2.example.com" in result.network_endpoints
        assert len(result.sms_events) > 0

    def test_upload_failure_raises_sandbox_error(self, fake_apk, high_risk_features):
        client = self._make_client()

        mock_requests = MagicMock()
        mock_requests.post.side_effect = Exception("Connection refused")

        with patch.dict("sys.modules", {"requests": mock_requests}):
            with pytest.raises(SandboxError, match="upload failed"):
                client.analyze(fake_apk, high_risk_features)

    def test_parse_report_handles_empty(self):
        from apkscan.dynamic_analysis.client import MobSFSandbox
        result = MobSFSandbox._parse_report({})
        assert result.captured is True
        assert result.api_trace == []
        assert result.network_endpoints == []

    def test_parse_report_handles_string_domains(self):
        from apkscan.dynamic_analysis.client import MobSFSandbox
        report = {
            "domains": ["evil.com", "bad.org"],
            "api_monitor": [],
        }
        result = MobSFSandbox._parse_report(report)
        assert "evil.com" in result.network_endpoints
        assert "bad.org" in result.network_endpoints


# ── Config validation ────────────────────────────────────────────────────


class TestConfig:
    def test_sandbox_settings_defaults(self):
        settings = Settings(env="test")
        assert settings.dynamic_enabled is False
        assert settings.sandbox_backend == "simulator"
        assert settings.sandbox_timeout == 60

    def test_sandbox_backend_validation(self):
        s = Settings(env="test", sandbox_backend="mobsf")
        assert s.sandbox_backend == "mobsf"

        s2 = Settings(env="test", sandbox_backend="simulator")
        assert s2.sandbox_backend == "simulator"

    def test_sandbox_timeout_custom(self):
        s = Settings(env="test", sandbox_timeout=120)
        assert s.sandbox_timeout == 120

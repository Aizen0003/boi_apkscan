"""CLI / local E2E tests (T0.20)."""

import json

import pytest

from apkscan.cli import main
from apkscan.schema import Permission, QuarkBehavior, YaraMatch
from apkscan.static_analysis.base import Analyzer, AnalyzerResult


class _MalAnalyzer(Analyzer):
    name = "fake_static"

    def is_available(self):
        return True

    def analyze(self, apk_path):
        return AnalyzerResult(
            permissions=[
                Permission(name="android.permission.BIND_ACCESSIBILITY_SERVICE"),
                Permission(name="android.permission.READ_SMS"),
                Permission(name="android.permission.SEND_SMS"),
                Permission(name="android.permission.SYSTEM_ALERT_WINDOW"),
                Permission(name="android.permission.INTERNET"),
                Permission(name="android.permission.REQUEST_INSTALL_PACKAGES"),
            ],
            quark_behaviors=[QuarkBehavior(crime="Send SMS in background", confidence_stage=5, score=4.0)],
            yara_matches=[YaraMatch(rule="android_overlay_banker", tags=["banker", "overlay"])],
        )


@pytest.fixture(autouse=True)
def _local_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("APKSCAN_ENV", "test")
    monkeypatch.setenv("APKSCAN_MOBSF_ENABLED", "false")
    monkeypatch.setenv("APKSCAN_LLM_ENABLED", "false")
    from apkscan.config import reload_settings

    reload_settings()
    yield
    reload_settings()


def test_analyze_benign_writes_reports(tmp_path, capsys):
    apk = tmp_path / "clean.apk"
    apk.write_bytes(b"PK\x03\x04 clean app")
    out = tmp_path / "r.json"
    pdf = tmp_path / "r.pdf"

    rc = main(["analyze", str(apk), "--no-genai", "--out", str(out), "--pdf", str(pdf)])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "BENIGN" in captured
    assert "purely deterministic" in captured  # no-genai path
    report = json.loads(out.read_text())
    assert report["verdict"]["verdict"] == "Benign"
    assert pdf.read_bytes()[:4] == b"%PDF"


def test_analyze_malicious_fail_on_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "apkscan.static_analysis.registry.default_analyzers", lambda settings=None: [_MalAnalyzer()]
    )
    apk = tmp_path / "evil.apk"
    apk.write_bytes(b"PK\x03\x04 evil")
    out = tmp_path / "r.json"

    rc = main(["analyze", str(apk), "--no-genai", "--fail-on-malicious", "--out", str(out)])
    assert rc == 2  # non-zero on malicious
    assert json.loads(out.read_text())["verdict"]["verdict"] == "Malicious"


def test_analyze_high_recall_mode_changes_operating_point(tmp_path, monkeypatch):
    # a mid-strength, *corroborated* sample (so it isn't permission-only capped):
    # score ~39 -> Suspicious under balanced, Malicious under high_recall.
    class _Mid(Analyzer):
        name = "mid"

        def is_available(self):
            return True

        def analyze(self, apk_path):
            return AnalyzerResult(
                permissions=[
                    Permission(name="android.permission.READ_PHONE_STATE"),
                    Permission(name="android.permission.INTERNET"),
                ],
                yara_matches=[YaraMatch(rule="generic_suspicious", tags=["heuristic"])],
            )

    monkeypatch.setattr("apkscan.static_analysis.registry.default_analyzers", lambda settings=None: [_Mid()])
    apk = tmp_path / "mid.apk"
    apk.write_bytes(b"PK mid")

    bal = tmp_path / "bal.json"
    main(["analyze", str(apk), "--no-genai", "--mode", "balanced", "--out", str(bal)])
    hr = tmp_path / "hr.json"
    main(["analyze", str(apk), "--no-genai", "--mode", "high_recall", "--out", str(hr)])

    assert json.loads(bal.read_text())["verdict"]["verdict"] == "Suspicious"
    assert json.loads(hr.read_text())["verdict"]["verdict"] == "Malicious"


def test_create_user_and_init_db(tmp_path, monkeypatch):
    monkeypatch.setenv("APKSCAN_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    from apkscan.config import reload_settings

    reload_settings()
    assert main(["init-db"]) == 0
    assert main(["create-user", "--username", "alice", "--password", "pw", "--role", "analyst"]) == 0
    # duplicate fails
    assert main(["create-user", "--username", "alice", "--password", "pw"]) == 1

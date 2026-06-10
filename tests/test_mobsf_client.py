"""MobSF client tests (T0.2) — mocked transport, no live server."""

import json

import httpx
import pytest

from apkscan.static_analysis.errors import MobSFUnavailable
from apkscan.static_analysis.mobsf_client import MobSFClient, _version_tuple


def _make_client(handler, **kw) -> MobSFClient:
    return MobSFClient(base_url="http://mobsf:8000", transport=httpx.MockTransport(handler), **kw)


def _report(version="4.4.6"):
    return {
        "version": version,
        "appsec": {
            "security_score": 35,
            "security_grade": "C",
            "high": [{"title": "x"}, {"title": "y"}],
            "warning": [{"title": "z"}],
            "secure": [],
            "info": [],
        },
        "trackers": {"detected_trackers": [{"name": "t1"}]},
        "domains": {
            "good.example.com": {"bad": "no"},
            "evil.example.com": {"bad": "yes"},
        },
        "firebase_urls": ["https://x.firebaseio.com"],
    }


def test_version_tuple_parsing():
    assert _version_tuple("v4.4.6") == (4, 4, 6)
    assert _version_tuple("4.4.6 Beta") == (4, 4, 6)
    assert _version_tuple(None) == ()
    assert _version_tuple("nonsense") == ()


def test_analyze_happy_path(tmp_path):
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK\x03\x04 fake apk")

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "abc123", "scan_type": "apk", "file_name": "s.apk"})
        if path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/v1/report_json":
            return httpx.Response(200, json=_report())
        return httpx.Response(404)

    with _make_client(handler) as client:
        summary, gaps = client.analyze(apk)

    assert summary.security_score == 35
    assert summary.grade == "C"
    assert summary.high == 2
    assert summary.medium == 1
    assert summary.trackers == 1
    assert summary.malware_domains == ["evil.example.com"]
    assert summary.firebase_urls == ["https://x.firebaseio.com"]
    assert gaps == []  # patched version -> no gap


def test_analyze_flags_underpatched_version(tmp_path):
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK fake")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/upload":
            return httpx.Response(200, json={"hash": "h"})
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(200, json=_report(version="4.3.0"))
        return httpx.Response(404)

    with _make_client(handler) as client:
        _summary, gaps = client.analyze(apk)

    assert len(gaps) == 1
    assert gaps[0].tool == "mobsf"
    assert gaps[0].severity == "error"
    assert "4.4.6" in gaps[0].reason


def test_transport_failure_raises_unavailable(tmp_path):
    apk = tmp_path / "s.apk"
    apk.write_bytes(b"PK")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _make_client(handler) as client:
        with pytest.raises(MobSFUnavailable):
            client.analyze(apk)


def test_download_pdf_returns_bytes(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/download_pdf":
            return httpx.Response(200, content=b"%PDF-1.4 fake")
        return httpx.Response(404)

    with _make_client(handler) as client:
        pdf = client.download_pdf("h")
    assert pdf.startswith(b"%PDF")


def test_summarize_report_tolerates_missing_fields():
    summary = MobSFClient.summarize_report({})
    assert summary.security_score is None
    assert summary.high == 0
    assert summary.malware_domains == []

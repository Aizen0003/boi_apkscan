"""API integration tests (T0.3 ingestion API, T0.17 auth/RBAC, T0.18 sign-off,
T0.19 export) — drives the eager worker through the real pipeline."""

import pytest
from fastapi.testclient import TestClient

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
            raw_strings=[("https://c2.firebaseio.com/x", "dex")],
        )


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("APKSCAN_ENV", "test")
    monkeypatch.setenv("APKSCAN_MOBSF_ENABLED", "false")
    monkeypatch.setenv("APKSCAN_LLM_ENABLED", "false")
    monkeypatch.setenv("APKSCAN_STORAGE_ROOT", str(tmp_path / "store"))
    monkeypatch.setenv("APKSCAN_DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("APKSCAN_SECRET_KEY", "test-secret-key-at-least-32-bytes-long-xx")
    from apkscan.config import reload_settings

    reload_settings()
    from apkscan.db import base

    base.configure(url=f"sqlite:///{tmp_path / 'api.db'}")
    base.init_db()
    from apkscan.jobs.celery_app import celery_app
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True

    from apkscan.auth.service import create_user
    from apkscan.db.models import Role

    with base.session_scope() as s:
        create_user(s, username="admin", password="adminpw", role=Role.ADMIN)
        create_user(s, username="ana", password="anapw", role=Role.ANALYST)
        create_user(s, username="vw", password="vwpw", role=Role.VIEWER)

    from apkscan.api.main import create_app

    with TestClient(create_app()) as c:
        yield c
    reload_settings()


def _token(client, user, pw):
    r = client.post("/auth/token", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def _upload(client, headers, content=b"PK\x03\x04 benign", priority="default"):
    return client.post(
        "/api/v1/samples",
        files={"file": ("x.apk", content, "application/octet-stream")},
        data={"priority": priority},
        headers=headers,
    )


# --- health / governance ---
def test_health_reports_no_commercial_egress(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["commercial_llm_egress"] is False
    assert body["dynamic_analysis"] is False


# --- auth + RBAC ---
def test_unauthenticated_upload_blocked(client):
    assert _upload(client, {}).status_code == 401


def test_bad_credentials_rejected(client):
    assert client.post("/auth/token", json={"username": "ana", "password": "wrong"}).status_code == 401


def test_viewer_cannot_upload(client):
    assert _upload(client, _token(client, "vw", "vwpw")).status_code == 403


# --- benign end-to-end (real pipeline, empty features) ---
def test_benign_flow_no_signoff(client):
    headers = _token(client, "ana", "anapw")
    assert _upload(client, {}).status_code == 401  # sanity: needs auth
    up = _upload(client, headers)
    assert up.status_code == 201, up.text
    job_id = up.json()["job_id"]
    job = client.get(f"/api/v1/jobs/{job_id}", headers=headers).json()
    assert job["status"] == "completed"
    report = client.get(f"/api/v1/reports/{job['report_id']}", headers=headers).json()
    assert report["verdict"]["verdict"] == "Benign"
    assert report["signoff"]["required"] is False
    # pdf + export retrievable
    assert client.get(f"/api/v1/reports/{job['report_id']}/pdf", headers=headers).content[:4] == b"%PDF"
    exp = client.get(f"/api/v1/reports/{job['report_id']}/export", headers=headers).json()
    assert exp["verdict"] == "Benign"
    assert exp["stix_bundle"]["type"] == "bundle"


def test_duplicate_upload_dedupes(client):
    headers = _token(client, "ana", "anapw")
    first = _upload(client, headers, content=b"PK identical").json()
    second = _upload(client, headers, content=b"PK identical").json()
    assert second["sample_sha256"] == first["sample_sha256"]
    assert second["deduped"] is True
    assert second["reused_job"] is True


# --- malicious end-to-end with sign-off (T0.18) ---
def test_malicious_flow_requires_signoff(client, monkeypatch):
    monkeypatch.setattr(
        "apkscan.static_analysis.registry.default_analyzers", lambda settings=None: [_MalAnalyzer()]
    )
    analyst = _token(client, "ana", "anapw")
    viewer = _token(client, "vw", "vwpw")

    up = _upload(client, analyst, content=b"PK malicious sample").json()
    job = client.get(f"/api/v1/jobs/{up['job_id']}", headers=analyst).json()
    assert job["status"] == "completed"
    rid = job["report_id"]

    report = client.get(f"/api/v1/reports/{rid}", headers=analyst).json()
    assert report["verdict"]["verdict"] == "Malicious"
    assert report["signoff"]["status"] == "pending"

    # findings searchable
    findings = client.get(f"/api/v1/findings?sample_sha256={up['sample_sha256']}", headers=analyst).json()
    assert any(f["category"] == "quark_behavior" for f in findings)

    # viewer cannot sign off
    assert client.post(f"/api/v1/reports/{rid}/signoff", json={"decision": "approve"}, headers=viewer).status_code == 403

    # analyst approves -> final
    r = client.post(f"/api/v1/reports/{rid}/signoff", json={"decision": "approve", "note": "confirmed"}, headers=analyst)
    assert r.status_code == 200
    assert r.json()["status"] == "final"
    # cannot sign off twice
    assert client.post(f"/api/v1/reports/{rid}/signoff", json={"decision": "approve"}, headers=analyst).status_code == 409


def test_admin_can_create_user_others_cannot(client):
    admin = _token(client, "admin", "adminpw")
    analyst = _token(client, "ana", "anapw")
    assert client.post("/auth/users", json={"username": "n", "password": "p", "role": "analyst"}, headers=analyst).status_code == 403
    assert client.post("/auth/users", json={"username": "n", "password": "p", "role": "analyst"}, headers=admin).status_code == 200

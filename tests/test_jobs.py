"""Job execution + persistence tests (T0.4 / T0.15 / T0.16)."""

import json

from apkscan import audit
from apkscan.config import Settings
from apkscan.db.models import AuditEvent, Finding, Job, JobStatus, Report, ReportStatus
from apkscan.genai.llm_client import ChatResponse
from apkscan.ingestion.service import ingest_sample
from apkscan.jobs.tasks import run_job
from apkscan.schema import Asset, Permission, QuarkBehavior, YaraMatch
from apkscan.static_analysis.base import Analyzer, AnalyzerResult


class _Mal(Analyzer):
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
            assets=[Asset(name="assets/p.dat", suspected_dex=True, suspected_encrypted=True, entropy=7.9)],
            raw_strings=[("https://c2.firebaseio.com/x", "dex")],
        )


class _FakeLLM:
    def is_available(self):
        return True

    def chat(self, messages, temperature=0.0):
        payload = {"summary": "banker", "claims": [{"text": "reads sms", "category": "behavior", "artifact_ids": ["perm:android.permission.READ_SMS"], "attack_techniques": ["T1636.004"]}], "recommendations": ["block c2"]}
        return ChatResponse(content=json.dumps(payload))


def _settings():
    return Settings(_env_file=None, env="test", mobsf_enabled=False)


def test_run_job_persists_report_findings_artifacts_audit(db_session, store, fake_apk):
    res = ingest_sample(src_path=fake_apk, file_name="m.apk", store=store, session=db_session, actor="analyst1")
    db_session.commit()

    status = run_job(res.job_id, settings=_settings(), store=store, analyzers=[_Mal()], llm_client=_FakeLLM(), code="public void f(){}", actor="analyst1")
    assert status == JobStatus.COMPLETED

    db_session.rollback()  # end snapshot
    db_session.expire_all()  # drop identity-map cache so we read run_job's commits

    job = db_session.get(Job, res.job_id)
    assert job.status == JobStatus.COMPLETED
    assert job.finished_at is not None

    report = db_session.query(Report).filter_by(job_id=res.job_id).one()
    assert report.verdict == "Malicious"
    assert report.requires_signoff is True
    assert report.status == ReportStatus.PENDING_SIGNOFF
    # artifacts stored on-prem
    assert store.exists(report.report_json_key)
    assert store.exists(report.report_pdf_key)
    # canonical JSON embedded
    assert report.score_json["verdict"] == "Malicious"

    # searchable findings index populated
    findings = db_session.query(Finding).filter_by(report_id=report.id).all()
    assert findings
    assert any(f.category == "quark_behavior" for f in findings)

    # audit trail complete + intact
    actions = [e.action for e in db_session.query(AuditEvent).order_by(AuditEvent.id).all()]
    for expected in ("sample.ingested", "job.created", "job.started", "analysis.scored", "report.created", "job.completed"):
        assert expected in actions
    assert audit.verify_chain(db_session) == []


def test_run_job_marks_failed_on_missing_sample(db_session, store):
    # a job id that doesn't exist -> ValueError path is internal; here test a job whose
    # storage object is absent to exercise the failure handler
    from apkscan.db.models import Job, Sample

    sample = Sample(sha256="0" * 64, storage_key="samples/missing.apk", file_size=1)
    job = Job(sample_sha256=sample.sha256)
    db_session.add_all([sample, job])
    db_session.commit()
    job_id = job.id

    status = run_job(job_id, settings=_settings(), store=store, analyzers=[_Mal()])
    db_session.rollback()
    db_session.expire_all()
    refreshed = db_session.get(Job, job_id)
    assert status == JobStatus.FAILED
    assert refreshed.status == JobStatus.FAILED
    assert refreshed.error

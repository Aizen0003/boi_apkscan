"""Celery tasks + the testable ``run_job`` core."""

import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from apkscan import audit
from apkscan.config import get_settings
from apkscan.db.base import session_scope
from apkscan.db.models import Job, JobStatus
from apkscan.jobs.celery_app import celery_app
from apkscan.jobs.persistence import persist_outcome
from apkscan.pipeline import run_analysis
from apkscan.schema import SampleMetadata
from apkscan.storage.factory import get_object_store


def _materialize(store, sample_row):
    """Return (apk_path, temp_to_cleanup_or_None) for a stored sample."""

    local = store.local_path(sample_row.storage_key)
    if local and Path(local).is_file():
        return str(local), None
    data = store.get_bytes(sample_row.storage_key)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
    tmp.write(data)
    tmp.close()
    return tmp.name, tmp.name


def run_job(job_id: str, *, settings=None, store=None, actor: str = "system", analyzers=None, llm_client=None, code=None, celery_task_id: Optional[str] = None) -> str:
    """Run analysis for a job and persist results. Returns the final job status."""

    settings = settings or get_settings()
    store = store or get_object_store(settings)

    # phase 1: mark running + snapshot sample metadata
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise ValueError(f"job not found: {job_id}")
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        if celery_task_id:
            job.celery_task_id = celery_task_id
        sample_row = job.sample
        sample_meta = SampleMetadata(
            sha256=sample_row.sha256,
            sha1=sample_row.sha1,
            md5=sample_row.md5,
            file_name=sample_row.file_name,
            file_size=sample_row.file_size or 0,
        )
        storage_key = sample_row.storage_key
        audit.record(session, action="job.started", actor=actor, sample_sha256=sample_row.sha256, job_id=job_id)

    # materialize + run pipeline (outside any DB transaction)
    cleanup = None
    try:
        local = store.local_path(storage_key)
        if local and Path(local).is_file():
            apk_path = str(local)
        else:
            data = store.get_bytes(storage_key)
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
            tmp.write(data)
            tmp.close()
            apk_path, cleanup = tmp.name, tmp.name

        report_id = uuid.uuid4().hex
        outcome = run_analysis(
            apk_path, sample_meta, settings=settings, analyzers=analyzers, llm_client=llm_client, code=code, report_id=report_id
        )

        with session_scope() as session:
            job = session.get(Job, job_id)
            persist_outcome(session, store, job, outcome, actor=actor)
            job.status = JobStatus.COMPLETED
            job.finished_at = datetime.now(timezone.utc)
            audit.record(session, action="job.completed", actor=actor, sample_sha256=job.sample_sha256, job_id=job_id)
        return JobStatus.COMPLETED
    except Exception as exc:  # noqa: BLE001 - record failure, don't crash the worker loop
        with session_scope() as session:
            job = session.get(Job, job_id)
            if job is not None:
                job.status = JobStatus.FAILED
                job.finished_at = datetime.now(timezone.utc)
                job.error = str(exc)
                audit.record(session, action="job.failed", actor=actor, sample_sha256=job.sample_sha256, job_id=job_id, detail={"error": str(exc)})
        return JobStatus.FAILED
    finally:
        if cleanup:
            try:
                os.unlink(cleanup)
            except OSError:
                pass


@celery_app.task(bind=True, name="apkscan.jobs.tasks.analyze_sample")
def analyze_sample(self, job_id: str) -> str:
    return run_job(job_id, celery_task_id=self.request.id)

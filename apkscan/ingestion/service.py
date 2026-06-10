"""Ingestion service: hash -> dedupe -> store -> create sample+job (T0.3 / FR1).

Samples may be live malware: the file is stored verbatim and never executed.
Dedupe is by sha256 (content-addressed). A duplicate upload reuses the existing
sample and any active/finished job rather than re-storing or re-analysing,
unless ``force_reanalyze`` is set.
"""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from apkscan import audit
from apkscan.config import Settings, get_settings
from apkscan.db.models import Job, JobStatus, Priority, Sample
from apkscan.ingestion.hashing import hash_file
from apkscan.storage.base import ObjectStore


@dataclass
class IngestResult:
    sample_sha256: str
    job_id: str
    deduped: bool          # the sample already existed
    reused_job: bool       # an existing job was returned instead of a new one
    storage_key: str


_REUSABLE = {JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.COMPLETED}


def ingest_sample(
    *,
    src_path: Path,
    file_name: str,
    store: ObjectStore,
    session: Session,
    actor: str = "system",
    priority: str = Priority.DEFAULT,
    force_reanalyze: bool = False,
    settings: Optional[Settings] = None,
) -> IngestResult:
    settings = settings or get_settings()
    src_path = Path(src_path)

    hashes = hash_file(src_path)
    sha256 = hashes["sha256"]
    storage_key = f"samples/{sha256}.apk"

    sample = session.get(Sample, sha256)
    deduped = sample is not None
    if sample is None:
        store.put_file(storage_key, src_path)  # write-once
        sample = Sample(
            sha256=sha256,
            sha1=hashes["sha1"],
            md5=hashes["md5"],
            file_name=file_name,
            file_size=int(hashes["size"]),
            storage_key=storage_key,
            received_by=actor,
            retention_until=_utcnow_plus(settings.retention_days),
        )
        session.add(sample)
        session.flush()
        audit.record(
            session,
            action="sample.ingested",
            actor=actor,
            sample_sha256=sha256,
            detail={"file_name": file_name, "file_size": sample.file_size, "md5": hashes["md5"]},
        )
    else:
        audit.record(
            session,
            action="sample.deduplicated",
            actor=actor,
            sample_sha256=sha256,
            detail={"file_name": file_name},
        )

    reused_job = False
    job: Optional[Job] = None
    if not force_reanalyze:
        job = session.execute(
            select(Job)
            .where(Job.sample_sha256 == sha256, Job.status.in_(_REUSABLE))
            .order_by(Job.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        reused_job = job is not None

    if job is None:
        job = Job(sample_sha256=sha256, priority=priority, created_by=actor, status=JobStatus.QUEUED)
        session.add(job)
        session.flush()
        audit.record(
            session,
            action="job.created",
            actor=actor,
            sample_sha256=sha256,
            job_id=job.id,
            detail={"priority": priority},
        )

    return IngestResult(
        sample_sha256=sha256,
        job_id=job.id,
        deduped=deduped,
        reused_job=reused_job,
        storage_key=storage_key,
    )


def _utcnow_plus(days: int):
    from datetime import datetime, timezone

    return datetime.now(timezone.utc) + timedelta(days=days)

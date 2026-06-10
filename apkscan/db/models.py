"""ORM models.

External-facing entities (Sample, Job, Report) use opaque string ids; Sample is
content-addressed by sha256. Status/role/priority are stored as portable strings
(constants below) rather than DB enums.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apkscan.db.base import Base


# --- constants ---
class Role:
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    ALL = {ADMIN, ANALYST, VIEWER}


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Priority:
    URGENT = "urgent"
    DEFAULT = "default"


class ReportStatus:
    DRAFT = "draft"
    PENDING_SIGNOFF = "pending_signoff"
    FINAL = "final"
    REJECTED = "rejected"


def _uuid() -> str:
    return uuid.uuid4().hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default=Role.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Sample(Base):
    __tablename__ = "samples"

    # content-addressed: the sha256 IS the id (natural dedupe key).
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    sha1: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    file_name: Mapped[Optional[str]] = mapped_column(String(512))
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    storage_key: Mapped[str] = mapped_column(String(512))
    package_name: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    # chain-of-custody
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    received_by: Mapped[Optional[str]] = mapped_column(String(150))
    retention_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    jobs: Mapped[list["Job"]] = relationship(back_populates="sample")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    sample_sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256"), index=True)
    status: Mapped[str] = mapped_column(String(32), default=JobStatus.QUEUED, index=True)
    priority: Mapped[str] = mapped_column(String(16), default=Priority.DEFAULT)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(64))
    created_by: Mapped[Optional[str]] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error: Mapped[Optional[str]] = mapped_column(Text)

    sample: Mapped["Sample"] = relationship(back_populates="jobs")
    report: Mapped[Optional["Report"]] = relationship(back_populates="job", uselist=False)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), index=True)
    sample_sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0.0")

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    requires_signoff: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default=ReportStatus.DRAFT, index=True)

    features_json: Mapped[dict] = mapped_column(JSON, default=dict)
    score_json: Mapped[dict] = mapped_column(JSON, default=dict)
    genai_json: Mapped[dict] = mapped_column(JSON, default=dict)
    report_json_key: Mapped[Optional[str]] = mapped_column(String(512))
    report_pdf_key: Mapped[Optional[str]] = mapped_column(String(512))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    job: Mapped["Job"] = relationship(back_populates="report")
    findings: Mapped[list["Finding"]] = relationship(back_populates="report")
    signoffs: Mapped[list["SignOff"]] = relationship(back_populates="report")


class Finding(Base):
    """Flattened, searchable evidence index (T0.15)."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"), index=True)
    sample_sha256: Mapped[str] = mapped_column(String(64), index=True)
    layer: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))
    detail: Mapped[str] = mapped_column(Text, default="")
    weight: Mapped[float] = mapped_column(Float, default=0.0)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    artifact_refs: Mapped[list] = mapped_column(JSON, default=list)

    report: Mapped["Report"] = relationship(back_populates="findings")


class SignOff(Base):
    __tablename__ = "signoffs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"), index=True)
    user: Mapped[str] = mapped_column(String(150))
    decision: Mapped[str] = mapped_column(String(16))  # approve | reject
    note: Mapped[str] = mapped_column(Text, default="")
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    report: Mapped["Report"] = relationship(back_populates="signoffs")


class AuditEvent(Base):
    """Append-only, hash-chained audit trail (T0.16)."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(150), default="system")
    action: Mapped[str] = mapped_column(String(128), index=True)
    sample_sha256: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    job_id: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), index=True)

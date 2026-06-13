"""Analysis routes: upload, job status, report retrieval, sign-off, export, search."""

import json
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from apkscan import audit
from apkscan.api.deps import get_store, require_analyst, require_reader
from apkscan.api.schemas import (
    ExportResponse,
    JobStatusResponse,
    ReportSummary,
    SignOffRequest,
    UploadResponse,
)
from apkscan.db.base import get_db
from apkscan.db.models import (
    Finding,
    Job,
    JobStatus,
    Priority,
    Report,
    ReportStatus,
    SignOff,
)
from apkscan.ingestion.service import ingest_sample
from apkscan.integration.export import build_export
from apkscan.jobs.submit import submit_job

router = APIRouter(prefix="/api/v1", tags=["analysis"])


@router.post("/samples", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
def upload_sample(
    file: UploadFile = File(...),
    priority: str = Form(Priority.DEFAULT),
    user=Depends(require_analyst),
    db: Session = Depends(get_db),
    store=Depends(get_store),
) -> UploadResponse:
    if priority not in (Priority.DEFAULT, Priority.URGENT):
        raise HTTPException(status_code=400, detail="priority must be 'default' or 'urgent'")

    # Enforce maximum file size to prevent OOM crash (e.g. 50MB)
    if file.size and file.size > 50 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="APK size exceeds 50MB limit (restricted to prevent server crash)",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    if Path(tmp_path).stat().st_size > 50 * 1024 * 1024:
        Path(tmp_path).unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="APK size exceeds 50MB limit (restricted to prevent server crash)",
        )

    try:
        result = ingest_sample(
            src_path=Path(tmp_path),
            file_name=file.filename or "upload.apk",
            store=store,
            session=db,
            actor=user.username,
            priority=priority,
        )
        db.commit()  # persist sample+job before dispatch (eager worker reads a fresh session)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    if not result.reused_job:
        submit_job(result.job_id, priority)

    return UploadResponse(
        sample_sha256=result.sample_sha256,
        job_id=result.job_id,
        deduped=result.deduped,
        reused_job=result.reused_job,
        status="queued",
    )


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
def job_status(job_id: str, user=Depends(require_reader), db: Session = Depends(get_db)) -> JobStatusResponse:
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    report_id = job.report.id if job.report else None
    return JobStatusResponse(
        job_id=job.id,
        sample_sha256=job.sample_sha256,
        status=job.status,
        priority=job.priority,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error=job.error,
        report_id=report_id,
    )


def _load_report(db: Session, report_id: str) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report


@router.get("/reports/{report_id}")
def get_report(report_id: str, user=Depends(require_reader), db: Session = Depends(get_db), store=Depends(get_store)):
    report = _load_report(db, report_id)
    if report.report_json_key and store.exists(report.report_json_key):
        return JSONResponse(content=json.loads(store.get_bytes(report.report_json_key)))
    # fallback: reconstruct minimal view from embedded JSON
    return JSONResponse(content={"score": report.score_json, "genai": report.genai_json})


@router.get("/reports/{report_id}/pdf")
def get_report_pdf(report_id: str, user=Depends(require_reader), db: Session = Depends(get_db), store=Depends(get_store)):
    report = _load_report(db, report_id)
    if not report.report_pdf_key or not store.exists(report.report_pdf_key):
        raise HTTPException(status_code=404, detail="PDF not available")
    headers = {
        "Content-Disposition": f'attachment; filename="apkscan_report_{report_id}.pdf"'
    }
    return Response(content=store.get_bytes(report.report_pdf_key), media_type="application/pdf", headers=headers)


@router.post("/reports/{report_id}/signoff", response_model=ReportSummary)
def signoff_report(
    report_id: str,
    body: SignOffRequest,
    user=Depends(require_analyst),
    db: Session = Depends(get_db),
) -> ReportSummary:
    report = _load_report(db, report_id)
    if not report.requires_signoff:
        raise HTTPException(status_code=400, detail="this report does not require sign-off")
    if report.status in (ReportStatus.FINAL, ReportStatus.REJECTED):
        raise HTTPException(status_code=409, detail=f"report already {report.status}")
    if body.decision not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'reject'")

    db.add(SignOff(report_id=report.id, user=user.username, decision=body.decision, note=body.note))
    report.status = ReportStatus.FINAL if body.decision == "approve" else ReportStatus.REJECTED
    audit.record(
        db,
        action="report.signed_off",
        actor=user.username,
        sample_sha256=report.sample_sha256,
        detail={"report_id": report.id, "decision": body.decision, "note": body.note},
    )
    return _summary(report)


@router.get("/reports/{report_id}/export", response_model=ExportResponse)
def export_report(report_id: str, user=Depends(require_reader), db: Session = Depends(get_db)) -> ExportResponse:
    report = _load_report(db, report_id)
    payload = build_export(
        sha256=report.sample_sha256, score_json=report.score_json, features_json=report.features_json
    )
    return ExportResponse(**payload)


@router.get("/samples", response_model=List[ReportSummary])
def list_reports(
    verdict: Optional[str] = None,
    sample_sha256: Optional[str] = None,
    limit: int = 100,
    user=Depends(require_reader),
    db: Session = Depends(get_db),
) -> List[ReportSummary]:
    stmt = select(Report).order_by(Report.created_at.desc()).limit(min(limit, 500))
    if verdict:
        stmt = stmt.where(Report.verdict == verdict)
    if sample_sha256:
        stmt = stmt.where(Report.sample_sha256 == sample_sha256)
    return [_summary(r) for r in db.execute(stmt).scalars().all()]


@router.get("/findings")
def search_findings(
    category: Optional[str] = None,
    technique: Optional[str] = None,
    sample_sha256: Optional[str] = None,
    limit: int = 200,
    user=Depends(require_reader),
    db: Session = Depends(get_db),
):
    stmt = select(Finding).limit(min(limit, 1000))
    if category:
        stmt = stmt.where(Finding.category == category)
    if sample_sha256:
        stmt = stmt.where(Finding.sample_sha256 == sample_sha256)
    rows = db.execute(stmt).scalars().all()
    if technique:
        rows = [f for f in rows if technique in (f.attack_techniques or [])]
    return [
        {
            "report_id": f.report_id,
            "sample_sha256": f.sample_sha256,
            "layer": f.layer,
            "category": f.category,
            "title": f.title,
            "weight": f.weight,
            "attack_techniques": f.attack_techniques,
        }
        for f in rows
    ]


def _summary(report: Report) -> ReportSummary:
    return ReportSummary(
        report_id=report.id,
        sample_sha256=report.sample_sha256,
        verdict=report.verdict,
        severity=report.severity,
        risk_score=report.risk_score,
        confidence=report.confidence,
        status=report.status,
        requires_signoff=report.requires_signoff,
    )

"""Persist an analysis outcome: artifacts -> object store, findings -> DB (T0.15)."""

from sqlalchemy.orm import Session

from apkscan import audit
from apkscan.db.models import Finding, Job, Report, ReportStatus
from apkscan.pipeline import AnalysisOutcome
from apkscan.reporting.json_report import render_json_bytes
from apkscan.reporting.pdf_report import render_pdf
from apkscan.storage.base import ObjectStore


def persist_outcome(
    session: Session,
    store: ObjectStore,
    job: Job,
    outcome: AnalysisOutcome,
    *,
    actor: str = "system",
) -> Report:
    sha = job.sample_sha256
    report_doc = outcome.report
    report_id = report_doc.report_id or job.id
    report_doc.report_id = report_id

    # 1) render + store artifacts (on-prem object store)
    json_key = f"reports/{sha}/{report_id}.json"
    pdf_key = f"reports/{sha}/{report_id}.pdf"
    store.put_bytes(json_key, render_json_bytes(report_doc), overwrite=True)
    try:
        store.put_bytes(pdf_key, render_pdf(report_doc), overwrite=True)
    except Exception as exc:  # noqa: BLE001 - PDF must never block persistence
        pdf_key = None
        audit.record(session, action="report.pdf_failed", actor=actor, sample_sha256=sha, job_id=job.id, detail={"error": str(exc)})

    score = outcome.score
    status = ReportStatus.PENDING_SIGNOFF if score.requires_signoff else ReportStatus.FINAL

    # 2) report row (searchable verdict + embedded canonical JSON)
    report = Report(
        id=report_id,
        job_id=job.id,
        sample_sha256=sha,
        risk_score=score.risk_score,
        verdict=score.verdict.value,
        severity=score.severity.value,
        confidence=score.confidence,
        requires_signoff=score.requires_signoff,
        status=status,
        features_json=outcome.features.model_dump(mode="json"),
        score_json=score.model_dump(mode="json"),
        genai_json=outcome.genai.model_dump(mode="json"),
        report_json_key=json_key,
        report_pdf_key=pdf_key,
    )
    session.add(report)
    session.flush()

    # 3) flattened findings index (T0.15)
    for item in score.evidence:
        session.add(
            Finding(
                report_id=report_id,
                sample_sha256=sha,
                layer=item.layer.value,
                category=item.category,
                title=item.title,
                detail=item.detail,
                weight=item.weight,
                attack_techniques=list(item.attack_techniques),
                artifact_refs=list(item.artifact_refs),
            )
        )

    # 4) audit every decision (T0.16)
    audit.record(
        session,
        action="analysis.scored",
        actor=actor,
        sample_sha256=sha,
        job_id=job.id,
        detail={
            "verdict": score.verdict.value,
            "severity": score.severity.value,
            "risk_score": score.risk_score,
            "confidence": score.confidence,
            "operating_mode": score.operating_mode,
            "indicator_count": len(score.evidence),
            "escalate": outcome.features.escalation.escalate,
            "genai_generated": outcome.genai.generated,
            "genai_grounding_failure_rate": outcome.genai.grounding_failure_rate,
        },
    )
    audit.record(
        session,
        action="report.created",
        actor=actor,
        sample_sha256=sha,
        job_id=job.id,
        detail={"report_id": report_id, "status": status, "requires_signoff": score.requires_signoff},
    )
    return report

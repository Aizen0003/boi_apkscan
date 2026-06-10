"""Job submission helper (priority-aware queue routing)."""

from typing import Optional

from apkscan.db.models import Priority


def submit_job(job_id: str, priority: str = Priority.DEFAULT) -> Optional[str]:
    """Dispatch a job to the worker. Returns the Celery task id (or None in eager).

    Urgent samples are routed to the dedicated ``urgent`` queue, which the worker
    drains ahead of ``default``.
    """

    from apkscan.jobs.tasks import analyze_sample

    queue = "urgent" if priority == Priority.URGENT else "default"
    async_result = analyze_sample.apply_async(args=[job_id], queue=queue)
    return getattr(async_result, "id", None)

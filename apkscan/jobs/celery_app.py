"""Celery application."""

from celery import Celery

from apkscan.config import get_settings

settings = get_settings()

celery_app = Celery(
    "apkscan",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["apkscan.jobs.tasks"],
)

celery_app.conf.update(
    task_always_eager=settings.celery_eager,
    task_eager_propagates=True,
    task_default_queue="default",
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    result_expires=settings.retention_days * 86400,
)

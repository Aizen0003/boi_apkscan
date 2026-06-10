"""Async job orchestration (Celery/Redis) — T0.4.

Priority is handled with two queues (``urgent`` and ``default``); the worker
consumes ``-Q urgent,default``. Eager mode (inline execution, no broker) is used
for local/CLI/test runs.
"""

from apkscan.jobs.celery_app import celery_app
from apkscan.jobs.submit import submit_job

__all__ = ["celery_app", "submit_job"]

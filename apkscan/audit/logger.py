"""Hash-chained audit log writer + verifier."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from apkscan.db.models import AuditEvent


def _ts_key(dt: datetime) -> str:
    """Canonical timestamp string, stable across DB backends.

    SQLite drops tzinfo on reload while Postgres preserves it; normalising to
    UTC-naive ISO makes the hash chain verify identically on either backend.
    """

    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat()


def _canonical(payload: Dict) -> str:
    """Deterministic JSON for hashing (sorted keys, str-coerced)."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(prev_hash: Optional[str], payload: Dict) -> str:
    h = hashlib.sha256()
    h.update((prev_hash or "").encode("utf-8"))
    h.update(_canonical(payload).encode("utf-8"))
    return h.hexdigest()


def record(
    session: Session,
    *,
    action: str,
    actor: str = "system",
    sample_sha256: Optional[str] = None,
    job_id: Optional[str] = None,
    detail: Optional[Dict] = None,
) -> AuditEvent:
    """Append one immutable audit event, chained to the previous entry."""

    prev = session.execute(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = prev.entry_hash if prev else None

    ts = datetime.now(timezone.utc)
    payload = {
        "ts": _ts_key(ts),
        "actor": actor,
        "action": action,
        "sample_sha256": sample_sha256,
        "job_id": job_id,
        "detail": detail or {},
    }
    event = AuditEvent(
        ts=ts,
        actor=actor,
        action=action,
        sample_sha256=sample_sha256,
        job_id=job_id,
        detail=detail or {},
        prev_hash=prev_hash,
        entry_hash=_entry_hash(prev_hash, payload),
    )
    session.add(event)
    session.flush()
    return event


def verify_chain(session: Session) -> List[int]:
    """Return the ids of any events whose hash chain is broken (empty == intact)."""

    broken: List[int] = []
    prev_hash: Optional[str] = None
    events = session.execute(select(AuditEvent).order_by(AuditEvent.id.asc())).scalars().all()
    for event in events:
        payload = {
            "ts": _ts_key(event.ts),
            "actor": event.actor,
            "action": event.action,
            "sample_sha256": event.sample_sha256,
            "job_id": event.job_id,
            "detail": event.detail or {},
        }
        expected = _entry_hash(prev_hash, payload)
        if event.prev_hash != prev_hash or event.entry_hash != expected:
            broken.append(event.id)
        prev_hash = event.entry_hash
    return broken

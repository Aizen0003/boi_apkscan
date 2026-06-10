"""Append-only, hash-chained audit logging (T0.16 / NFR2).

Every indicator, score contribution, and decision is recorded as an immutable
``AuditEvent``. Each entry's hash chains to the previous one, making silent
tampering detectable.
"""

from apkscan.audit.logger import record, verify_chain

__all__ = ["record", "verify_chain"]

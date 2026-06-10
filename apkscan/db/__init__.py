"""Persistence layer (SQLAlchemy 2.0).

Portable across SQLite (local/CLI/test) and Postgres (stack). Tables are created
with ``init_db``; an Alembic migration history is deferred to deployment.
"""

from apkscan.db.base import configure, get_db, get_engine, init_db, session_scope
from apkscan.db import models

__all__ = ["configure", "get_db", "get_engine", "init_db", "session_scope", "models"]

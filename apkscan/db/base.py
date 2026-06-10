"""Engine / session management."""

from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from apkscan.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None


def get_engine(url: Optional[str] = None, echo: bool = False) -> Engine:
    url = url or get_settings().database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, echo=echo, future=True, pool_pre_ping=True, connect_args=connect_args)


def configure(engine: Optional[Engine] = None, url: Optional[str] = None) -> Engine:
    """(Re)configure the global engine + session factory."""

    global _engine, _SessionLocal
    _engine = engine or get_engine(url)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)
    return _engine


def _ensure_configured() -> sessionmaker:
    if _SessionLocal is None:
        configure()
    assert _SessionLocal is not None
    return _SessionLocal


def new_session() -> Session:
    """Return a fresh Session (caller manages commit/close). Used by CLI/tests."""

    return _ensure_configured()()


def is_configured() -> bool:
    return _engine is not None


def init_db(engine: Optional[Engine] = None) -> Engine:
    """Create all tables. Imports models so they register on the metadata."""

    from apkscan.db import models  # noqa: F401

    engine = engine or _engine or configure()
    Base.metadata.create_all(engine)
    return engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for workers/CLI."""

    factory = _ensure_configured()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: a session per request."""

    factory = _ensure_configured()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

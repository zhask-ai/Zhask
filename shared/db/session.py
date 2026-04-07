"""
shared.db.session
------------------
SQLAlchemy engine + session factory.

Configuration (via environment variables):
    DATABASE_URL   — full Postgres DSN, e.g.:
                     postgresql://integrishield:secret@postgres:5432/integrishield
                     Defaults to the POC docker-compose values if not set.

Usage in FastAPI (M01):
    from shared.db import get_session
    from sqlalchemy.orm import Session
    from fastapi import Depends

    @router.post("/rfc/proxy")
    def proxy(db: Session = Depends(get_session)):
        db.add(AuditEvent(...))
        db.commit()

Usage in scripts / tests:
    with SessionLocal() as session:
        session.add(AuditEvent(...))
        session.commit()

Owned by Dev 1.
"""

import os
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from shared.telemetry import get_logger

logger = get_logger(__name__)

_DEFAULT_DATABASE_URL = (
    "postgresql://integrishield:integrishield@postgres:5432/integrishield"
)


def _get_database_url() -> str:
    url = os.getenv("DATABASE_URL", _DEFAULT_DATABASE_URL)
    if url == _DEFAULT_DATABASE_URL:
        logger.warning(
            "DATABASE_URL not set — using POC default. "
            "Set DATABASE_URL in production."
        )
    return url


# Module-level engine — created once, shared across all requests.
engine = create_engine(
    _get_database_url(),
    pool_pre_ping=True,       # auto-reconnect on stale connections
    pool_size=5,              # small pool for POC
    max_overflow=10,
    echo=False,               # set to True locally to see SQL
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_session() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a DB session and always closes it.

    The session is committed by the route handler on success;
    it is rolled back automatically if an exception propagates.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_tables() -> None:
    """
    Create all tables that don't yet exist in the database.
    Called once at M01 startup (idempotent — safe to call multiple times).
    """
    from shared.db.models import Base  # local import avoids circular dep at module load

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ensured (create_all complete)")

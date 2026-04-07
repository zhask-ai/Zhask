"""
shared.db — database models and session factory for IntegriShield.
Owned by Dev 1.

POC: PostgreSQL via SQLAlchemy (sync, for simplicity).
     One table: audit_events — every RFC call that passes through M01.

Post-funding: add async sessions (SQLAlchemy 2.x async), migrations via Alembic.
"""

from shared.db.session import get_session, engine, SessionLocal
from shared.db.models import Base, AuditEvent

__all__ = ["get_session", "engine", "SessionLocal", "Base", "AuditEvent"]

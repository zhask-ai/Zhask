"""
shared.db.models
-----------------
SQLAlchemy ORM models for IntegriShield.

audit_events table
------------------
Every RFC call intercepted by M01 is written here.  This is the
permanent audit trail — even if Redis loses the event, the DB has it.

Dev 4's dashboard queries this table directly for the audit log panel.

Owned by Dev 1.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    """
    One row per SAP RFC call intercepted by M01.

    Columns mirror the api_call_event JSON schema so that M01 can write
    a row and publish a Redis event from the same in-memory dict.
    """

    __tablename__ = "audit_events"

    # Primary key — matches event_id in the Redis event so rows are
    # traceable across the bus.
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    # --- Core RFC call fields (mirrors api_call_event schema) ---
    rfc_function   = Column(String(128), nullable=False, index=True)
    client_ip      = Column(String(45),  nullable=False)          # IPv4/IPv6
    user_id        = Column(String(64),  nullable=False, index=True)
    timestamp      = Column(DateTime(timezone=True), nullable=False, index=True)
    rows_returned  = Column(Integer, nullable=False, default=0)
    response_time_ms = Column(Integer, nullable=False, default=0)
    status         = Column(
        Enum("SUCCESS", "ERROR", "TIMEOUT", name="rfc_status"),
        nullable=False,
    )
    sap_system     = Column(String(10), nullable=True)

    # --- Detection flags (set by M01 detectors before insert) ---
    is_off_hours         = Column(Boolean, nullable=False, default=False)
    is_bulk_extraction   = Column(Boolean, nullable=False, default=False)
    is_shadow_endpoint   = Column(Boolean, nullable=False, default=False)

    # --- Metadata ---
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
    )
    raw_payload = Column(Text, nullable=True)  # full JSON for debugging

    # Composite index for the dashboard's most common query:
    # "show me all flagged events in the last N hours"
    __table_args__ = (
        Index(
            "ix_audit_events_flags_ts",
            "is_off_hours",
            "is_bulk_extraction",
            "is_shadow_endpoint",
            "timestamp",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id} rfc={self.rfc_function} "
            f"user={self.user_id} ts={self.timestamp}>"
        )

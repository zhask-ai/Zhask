"""SQLAlchemy ORM models for M10 Incident Response."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class IncidentRow(Base):
    __tablename__ = "m10_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(String(64), nullable=False, unique=True, index=True)
    alert_event_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    severity = Column(
        Enum("critical", "high", "medium", "low", name="m10_incident_severity"),
        nullable=False,
        index=True,
    )
    status = Column(
        Enum("open", "in_progress", "contained", "resolved", "closed", name="m10_incident_status"),
        nullable=False,
        default="open",
        index=True,
    )
    scenario = Column(String(64), nullable=False, default="")
    source_ip = Column(String(45), nullable=False, default="")
    user_id = Column(String(64), nullable=False, default="")
    tenant_id = Column(String(64), nullable=False, default="")
    playbook_id = Column(String(64), nullable=False, default="")
    containment_applied = Column(Boolean, nullable=False, default=False)
    notes = Column(Text, nullable=False, default="")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_m10_incidents_status_severity", "status", "severity", "created_at"),
    )


class PlaybookExecRow(Base):
    __tablename__ = "m10_playbook_executions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id = Column(String(64), nullable=False, unique=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    playbook_id = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    success = Column(Boolean, nullable=False, default=True)
    detail = Column(Text, nullable=False, default="")
    executed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
    )

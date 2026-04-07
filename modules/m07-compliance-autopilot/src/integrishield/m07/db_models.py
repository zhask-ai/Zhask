"""SQLAlchemy ORM models for M07 Compliance Autopilot."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class EvidenceRow(Base):
    __tablename__ = "m07_evidence_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = Column(String(64), nullable=False, unique=True, index=True)
    control_id = Column(String(64), nullable=False, index=True)
    framework = Column(String(16), nullable=False)
    event_id = Column(String(64), nullable=False)
    evidence_type = Column(String(32), nullable=False)
    tenant_id = Column(String(64), nullable=False, default="")
    summary = Column(Text, nullable=False)
    is_violation = Column(Boolean, nullable=False, default=False)
    collected_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
        index=True,
    )

    __table_args__ = (
        Index("ix_m07_evidence_ctrl_ts", "control_id", "collected_at"),
    )


class AssessmentRow(Base):
    __tablename__ = "m07_control_assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id = Column(String(64), nullable=False)
    tenant_id = Column(String(64), nullable=False, default="")
    framework = Column(String(16), nullable=False)
    status = Column(
        Enum("compliant", "non_compliant", "needs_review", "not_assessed", name="m07_ctrl_status"),
        nullable=False,
        default="not_assessed",
    )
    evidence_count = Column(Integer, nullable=False, default=0)
    violation_count = Column(Integer, nullable=False, default=0)
    last_violation_at = Column(DateTime(timezone=True), nullable=True)
    last_assessed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(tz=timezone.utc),
    )

    __table_args__ = (
        Index("ix_m07_assessment_ctrl_tenant", "control_id", "tenant_id", unique=True),
    )

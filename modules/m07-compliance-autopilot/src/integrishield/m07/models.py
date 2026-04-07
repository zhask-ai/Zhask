"""Pydantic data models for M07 Compliance Autopilot."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Framework(str, Enum):
    SOX = "sox"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"


class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NEEDS_REVIEW = "needs_review"
    NOT_ASSESSED = "not_assessed"


class EvidenceType(str, Enum):
    ALERT = "alert"
    ANOMALY = "anomaly"
    DLP_VIOLATION = "dlp_violation"
    API_CALL_LOG = "api_call_log"
    SHADOW_ENDPOINT = "shadow_endpoint"
    ACCESS_DENIAL = "access_denial"


class ControlDefinition(BaseModel):
    control_id: str
    framework: Framework
    title: str
    description: str
    evidence_streams: list[str]
    violation_streams: list[str] = []
    remediation_guidance: str = ""


class EvidenceItem(BaseModel):
    evidence_id: str
    control_id: str
    framework: Framework
    event_id: str
    evidence_type: EvidenceType
    tenant_id: str = ""
    summary: str
    raw_payload: dict[str, Any] = {}
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    is_violation: bool = False


class ControlAssessment(BaseModel):
    control_id: str
    framework: Framework
    title: str = ""
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    evidence_count: int = 0
    violation_count: int = 0
    last_violation_at: datetime | None = None
    last_assessed_at: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str = ""


class ComplianceSummary(BaseModel):
    framework: Framework
    total_controls: int
    compliant: int
    non_compliant: int
    needs_review: int
    not_assessed: int
    compliance_percentage: float
    as_of: datetime = Field(default_factory=datetime.utcnow)


class ReportRequest(BaseModel):
    framework: Framework
    tenant_id: str = ""
    from_date: datetime | None = None
    to_date: datetime | None = None
    format: str = "json"


class ComplianceAlertEvent(BaseModel):
    """Published to Redis when a control violation is detected."""

    event_id: str
    control_id: str
    framework: Framework
    violation_summary: str
    severity: str = "medium"
    tenant_id: str = ""
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m07-compliance-autopilot"


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m07-compliance-autopilot"
    version: str = "0.1.0"
    redis_connected: bool = False
    db_connected: bool = False
    controls_loaded: int = 0

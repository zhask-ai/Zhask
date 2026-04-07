"""Pydantic data models for M10 Incident Response."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class PlaybookAction(str, Enum):
    LOG_EVENT = "log_event"
    NOTIFY_SLACK = "notify_slack"
    NOTIFY_PAGERDUTY = "notify_pagerduty"
    FORWARD_SIEM = "forward_siem"
    AUTO_CONTAIN = "auto_contain"
    ESCALATE = "escalate"


class Incident(BaseModel):
    incident_id: str
    alert_event_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    scenario: str = ""
    source_ip: str = ""
    user_id: str = ""
    tenant_id: str = ""
    playbook_id: str = ""
    containment_applied: bool = False
    notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None


class PlaybookDefinition(BaseModel):
    playbook_id: str
    name: str
    trigger_severity: list[IncidentSeverity]
    trigger_scenarios: list[str]
    actions: list[PlaybookAction]
    auto_contain: bool = False
    notify_channels: list[str] = []
    siem_forward: bool = False


class PlaybookExecutionLog(BaseModel):
    execution_id: str
    incident_id: str
    playbook_id: str
    action: PlaybookAction
    success: bool
    detail: str = ""
    executed_at: datetime = Field(default_factory=datetime.utcnow)


class IncidentUpdateRequest(BaseModel):
    status: IncidentStatus | None = None
    notes: str | None = None


class IncidentListResponse(BaseModel):
    incidents: list[Incident]
    total: int
    open_count: int


class IncidentStats(BaseModel):
    open: int = 0
    in_progress: int = 0
    contained: int = 0
    resolved: int = 0
    closed: int = 0
    critical: int = 0
    total: int = 0


class IncidentEvent(BaseModel):
    """Published to Redis when incident state changes."""

    event_id: str
    incident_id: str
    alert_event_id: str
    action: str
    severity: IncidentSeverity
    tenant_id: str = ""
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m10-incident-response"


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m10-incident-response"
    version: str = "0.1.0"
    redis_connected: bool = False
    db_connected: bool = False
    open_incidents: int = 0

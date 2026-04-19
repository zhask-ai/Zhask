"""Pydantic models — request, response, and event payloads for M12 Rules Engine."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    MEDIUM = "medium"
    LOW = "low"


class Scenario(str, Enum):
    BULK_EXTRACTION = "bulk-extraction"
    OFF_HOURS_RFC = "off-hours-rfc"
    SHADOW_ENDPOINT = "shadow-endpoint"
    VELOCITY_ANOMALY = "velocity-anomaly"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    GEO_ANOMALY = "geo-anomaly"
    DATA_STAGING = "data-staging"
    CREDENTIAL_ABUSE = "credential-abuse"


# ---------------------------------------------------------------------------
# Inbound event (consumed from Redis)
# ---------------------------------------------------------------------------

class ApiCallEvent(BaseModel):
    """Raw event from M01 API Gateway Shield."""

    event_id: str
    source_ip: str = ""
    timestamp_utc: datetime | None = None
    bytes_out: int = 0
    off_hours: bool = False
    unknown_endpoint: bool = False


# ---------------------------------------------------------------------------
# Alert (produced by rules evaluation)
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """Alert output after rules evaluation."""

    event_id: str | None = None
    scenario: Scenario
    severity: Severity
    message: str = ""
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m12-rules-engine"
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# API request / response
# ---------------------------------------------------------------------------

class EvaluateRequest(BaseModel):
    """Manually submit an event for evaluation via the REST API."""

    event_id: str
    bytes_out: int = 0
    off_hours: bool = False
    unknown_endpoint: bool = False
    source_ip: str = ""
    rfc_function: str = ""
    account_type: str = ""
    credential_id: str = ""


class EvaluateResponse(BaseModel):
    alert: dict | None = None
    matched: bool = False


class AlertsListResponse(BaseModel):
    alerts: list[Alert]
    total: int


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m12-rules-engine"
    version: str = "0.1.0"
    redis_connected: bool = False

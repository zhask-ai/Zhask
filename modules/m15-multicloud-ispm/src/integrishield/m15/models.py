"""Pydantic models — request, response, and event payloads for M15 Multi-Cloud ISPM."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Cloud security finding
# ---------------------------------------------------------------------------

class CloudFinding(BaseModel):
    """A security finding from any cloud provider."""

    provider: CloudProvider
    resource_id: str
    control_id: str
    severity: FindingSeverity = FindingSeverity.LOW
    description: str = ""
    region: str = ""
    tenant_id: str = ""


class NormalizedFinding(BaseModel):
    """Provider-agnostic normalized finding with risk score."""

    provider: CloudProvider
    resource_id: str
    control_id: str
    risk_score: int = 0
    raw_severity: FindingSeverity = FindingSeverity.LOW
    description: str = ""
    region: str = ""
    normalized_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Event payload (published to Redis)
# ---------------------------------------------------------------------------

class CloudPostureEvent(BaseModel):
    """Event published to integrishield:cloud_posture_events."""

    event_id: str
    provider: CloudProvider
    resource_id: str
    control_id: str
    risk_score: int
    raw_severity: str
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m15-multicloud-ispm"


# ---------------------------------------------------------------------------
# API responses
# ---------------------------------------------------------------------------

class PostureSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    by_provider: dict[str, int] = Field(default_factory=dict)
    avg_risk_score: float = 0.0


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m15-multicloud-ispm"
    version: str = "0.1.0"

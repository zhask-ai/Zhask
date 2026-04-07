"""Pydantic models — request, response, and event payloads for M04 Zero-Trust Fabric."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class AccessDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"


class FailedControl(str, Enum):
    DEVICE_TRUST = "device_trust"
    GEO_POLICY = "geo_policy"
    MFA_REQUIRED = "mfa_required"
    SESSION_EXPIRED = "session_expired"


# ---------------------------------------------------------------------------
# Access evaluation
# ---------------------------------------------------------------------------

class AccessRequest(BaseModel):
    """Inbound access evaluation request."""

    user_id: str
    source_ip: str
    device_trusted: bool = False
    geo_allowed: bool = True
    mfa_verified: bool = False
    session_age_minutes: int = 0
    tenant_id: str = ""
    resource: str = ""


class AccessResult(BaseModel):
    """Result of a zero-trust access evaluation."""

    decision: AccessDecision
    risk_score: int = 0
    reason: str = ""
    failed_controls: list[FailedControl] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Event payload (published to Redis)
# ---------------------------------------------------------------------------

class ZeroTrustEvent(BaseModel):
    """Event published to integrishield:zero_trust_events."""

    event_id: str
    user_id: str
    source_ip: str
    decision: AccessDecision
    risk_score: int
    failed_controls: list[str]
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m04-zero-trust-fabric"


# ---------------------------------------------------------------------------
# API responses
# ---------------------------------------------------------------------------

class PolicyStatsResponse(BaseModel):
    total_evaluations: int = 0
    denied: int = 0
    allowed: int = 0
    challenged: int = 0
    avg_risk_score: float = 0.0


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m04-zero-trust-fabric"
    version: str = "0.1.0"

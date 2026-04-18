"""Pydantic models — request, response, and event payloads for M06 Credential Vault."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class SecretStatus(str, Enum):
    ACTIVE = "active"
    ROTATING = "rotating"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RotationUrgency(str, Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Secret management
# ---------------------------------------------------------------------------

class SecretMetadata(BaseModel):
    """Public metadata about a secret (never exposes the value)."""

    key: str
    status: SecretStatus = SecretStatus.ACTIVE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    rotated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    rotation_urgency: RotationUrgency = RotationUrgency.OK
    owner_module: str = ""
    tenant_id: str = ""


class RotateRequest(BaseModel):
    """Request to rotate a secret."""

    key: str
    reason: str = "scheduled"


class RotateResponse(BaseModel):
    key: str
    rotated: bool
    previous_age_days: int = 0
    new_status: SecretStatus = SecretStatus.ACTIVE


# ---------------------------------------------------------------------------
# Event payload (published to Redis)
# ---------------------------------------------------------------------------

class CredentialEvent(BaseModel):
    """Event published to integrishield:credential_events."""

    event_id: str
    key: str
    action: str  # "rotated", "created", "revoked", "expiry_warning"
    status: SecretStatus
    tenant_id: str = ""
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m06-credential-vault"


# ---------------------------------------------------------------------------
# API responses
# ---------------------------------------------------------------------------

class VaultStatsResponse(BaseModel):
    total_secrets: int = 0
    active: int = 0
    expiring_soon: int = 0
    expired: int = 0
    revoked: int = 0


class RevokeResponse(BaseModel):
    key: str
    revoked: bool


class CredAccessEvent(BaseModel):
    """Audit event published to integrishield:cred_access on every secret access."""

    event_id: str
    key: str
    action: str  # "created", "read", "read:m05", "rotated:scheduled", "revoked"
    tenant_id: str = ""
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m06-credential-vault"


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m06-credential-vault"
    version: str = "0.1.0"

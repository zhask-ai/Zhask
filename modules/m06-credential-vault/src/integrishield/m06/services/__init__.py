"""Credential vault service — secret lifecycle management for M06."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from integrishield.m06.config import settings
from integrishield.m06.models import (
    CredentialEvent,
    RotateResponse,
    RotationUrgency,
    SecretMetadata,
    SecretStatus,
)

# In-memory vault store (replaced by Postgres / HashiCorp Vault in MVP)
_vault: dict[str, dict] = {}


def store_secret(key: str, value: str, owner_module: str = "", tenant_id: str = "") -> SecretMetadata:
    """Store a new secret and return its metadata."""
    now = datetime.now(timezone.utc)
    _vault[key] = {
        "value": value,
        "status": SecretStatus.ACTIVE,
        "created_at": now,
        "rotated_at": now,
        "owner_module": owner_module,
        "tenant_id": tenant_id,
    }
    return _get_metadata(key)


def rotate_secret(key: str, new_value: str, reason: str = "scheduled") -> RotateResponse:
    """Rotate an existing secret, returning rotation details."""
    if key not in _vault:
        return RotateResponse(key=key, rotated=False)

    entry = _vault[key]
    old_age = (datetime.now(timezone.utc) - entry["rotated_at"]).days
    entry["value"] = new_value
    entry["rotated_at"] = datetime.now(timezone.utc)
    entry["status"] = SecretStatus.ACTIVE

    return RotateResponse(
        key=key,
        rotated=True,
        previous_age_days=old_age,
        new_status=SecretStatus.ACTIVE,
    )


def needs_rotation(key: str) -> RotationUrgency:
    """Check whether a secret needs rotation based on its age."""
    if key not in _vault:
        return RotationUrgency.CRITICAL

    age = datetime.now(timezone.utc) - _vault[key]["rotated_at"]

    if age > timedelta(days=settings.max_secret_age_days):
        return RotationUrgency.CRITICAL
    elif age > timedelta(days=settings.max_secret_age_days - settings.rotation_warning_days):
        return RotationUrgency.WARNING
    return RotationUrgency.OK


def list_secrets() -> list[SecretMetadata]:
    """Return metadata for all stored secrets."""
    return [_get_metadata(k) for k in _vault]


def get_stats() -> dict:
    """Vault statistics summary."""
    metas = list_secrets()
    return {
        "total_secrets": len(metas),
        "active": sum(1 for m in metas if m.status == SecretStatus.ACTIVE),
        "expiring_soon": sum(1 for m in metas if m.rotation_urgency == RotationUrgency.WARNING),
        "expired": sum(1 for m in metas if m.rotation_urgency == RotationUrgency.CRITICAL),
        "revoked": sum(1 for m in metas if m.status == SecretStatus.REVOKED),
    }


def to_event(key: str, action: str) -> CredentialEvent:
    """Create a publishable credential event."""
    entry = _vault.get(key, {})
    return CredentialEvent(
        event_id=str(uuid4()),
        key=key,
        action=action,
        status=entry.get("status", SecretStatus.ACTIVE),
        tenant_id=entry.get("tenant_id", ""),
    )


def _get_metadata(key: str) -> SecretMetadata:
    entry = _vault[key]
    return SecretMetadata(
        key=key,
        status=entry["status"],
        created_at=entry["created_at"],
        rotated_at=entry["rotated_at"],
        rotation_urgency=needs_rotation(key),
        owner_module=entry.get("owner_module", ""),
        tenant_id=entry.get("tenant_id", ""),
    )

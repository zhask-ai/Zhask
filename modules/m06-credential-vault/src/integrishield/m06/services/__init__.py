"""Credential vault service — secret lifecycle management for M06."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import redis as redis_lib

from integrishield.m06.backends import get_backend
from integrishield.m06.config import settings
from integrishield.m06.models import (
    CredAccessEvent,
    CredentialEvent,
    RotateResponse,
    RotationUrgency,
    SecretMetadata,
    SecretStatus,
)

logger = logging.getLogger(__name__)

# Lazy-initialised singletons
_backend = None
_redis: redis_lib.Redis | None = None


def _get_backend():
    global _backend
    if _backend is None:
        _backend = get_backend()
        logger.info("m06 vault backend initialised: %s", type(_backend).__name__)
    return _backend


def _get_redis() -> redis_lib.Redis | None:
    global _redis
    if _redis is not None:
        return _redis
    try:
        r = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
        r.ping()
        _redis = r
    except Exception as exc:
        logger.warning("m06 Redis unavailable — audit events disabled: %s", exc)
    return _redis


def _publish_audit(key: str, action: str, tenant_id: str = "") -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        event = CredAccessEvent(
            event_id=str(uuid4()),
            key=key,
            action=action,
            tenant_id=tenant_id,
        )
        r.xadd(
            settings.cred_access_stream,
            {"data": event.model_dump_json()},
            maxlen=50_000,
            approximate=True,
        )
    except Exception:
        logger.exception("Failed to publish audit event for key='%s'", key)


def _entry_to_metadata(key: str, entry: dict) -> SecretMetadata:
    status = SecretStatus(entry.get("status", SecretStatus.ACTIVE))
    created_at = entry.get("created_at", datetime.now(timezone.utc))
    rotated_at = entry.get("rotated_at", datetime.now(timezone.utc))
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    if isinstance(rotated_at, str):
        rotated_at = datetime.fromisoformat(rotated_at)
    age = datetime.now(timezone.utc) - rotated_at
    if age > timedelta(days=settings.max_secret_age_days):
        urgency = RotationUrgency.CRITICAL
    elif age > timedelta(days=settings.max_secret_age_days - settings.rotation_warning_days):
        urgency = RotationUrgency.WARNING
    else:
        urgency = RotationUrgency.OK
    return SecretMetadata(
        key=key,
        status=status,
        created_at=created_at,
        rotated_at=rotated_at,
        rotation_urgency=urgency,
        owner_module=entry.get("owner_module", ""),
        tenant_id=entry.get("tenant_id", ""),
    )


# ---------------------------------------------------------------------------
# Public API — preserves existing contract, adds read_secret / revoke_secret
# ---------------------------------------------------------------------------

def store_secret(key: str, value: str, owner_module: str = "", tenant_id: str = "") -> SecretMetadata:
    entry = _get_backend().store(key, value, owner_module, tenant_id)
    _publish_audit(key, "created", tenant_id)
    return _entry_to_metadata(key, entry)


def read_secret(key: str, requester: str = "") -> str | None:
    """Return the raw secret value — for m05 driver credential fetch."""
    value = _get_backend().read(key)
    entry = _get_backend().get_entry(key)
    tenant_id = entry.get("tenant_id", "") if entry else ""
    action = f"read:{requester}" if requester else "read"
    _publish_audit(key, action, tenant_id)
    return value


def rotate_secret(key: str, new_value: str, reason: str = "scheduled") -> RotateResponse:
    entry = _get_backend().get_entry(key)
    if entry is None:
        return RotateResponse(key=key, rotated=False)
    rotated_at = entry.get("rotated_at", datetime.now(timezone.utc))
    if isinstance(rotated_at, str):
        rotated_at = datetime.fromisoformat(rotated_at)
    old_age = (datetime.now(timezone.utc) - rotated_at).days
    updated = _get_backend().rotate(key, new_value)
    if updated is None:
        return RotateResponse(key=key, rotated=False)
    _publish_audit(key, f"rotated:{reason}", entry.get("tenant_id", ""))
    return RotateResponse(
        key=key,
        rotated=True,
        previous_age_days=old_age,
        new_status=SecretStatus.ACTIVE,
    )


def revoke_secret(key: str) -> bool:
    entry = _get_backend().get_entry(key)
    ok = _get_backend().revoke(key)
    if ok and entry:
        _publish_audit(key, "revoked", entry.get("tenant_id", ""))
    return ok


def needs_rotation(key: str) -> RotationUrgency:
    entry = _get_backend().get_entry(key)
    if entry is None:
        return RotationUrgency.CRITICAL
    rotated_at = entry.get("rotated_at", datetime.now(timezone.utc))
    if isinstance(rotated_at, str):
        rotated_at = datetime.fromisoformat(rotated_at)
    age = datetime.now(timezone.utc) - rotated_at
    if age > timedelta(days=settings.max_secret_age_days):
        return RotationUrgency.CRITICAL
    if age > timedelta(days=settings.max_secret_age_days - settings.rotation_warning_days):
        return RotationUrgency.WARNING
    return RotationUrgency.OK


def list_secrets() -> list[SecretMetadata]:
    entries = _get_backend().list_entries()
    return [_entry_to_metadata(e["key"], e) for e in entries]


def get_stats() -> dict:
    metas = list_secrets()
    return {
        "total_secrets": len(metas),
        "active": sum(1 for m in metas if m.status == SecretStatus.ACTIVE),
        "expiring_soon": sum(1 for m in metas if m.rotation_urgency == RotationUrgency.WARNING),
        "expired": sum(1 for m in metas if m.rotation_urgency == RotationUrgency.CRITICAL),
        "revoked": sum(1 for m in metas if m.status == SecretStatus.REVOKED),
    }


def to_event(key: str, action: str) -> CredentialEvent:
    entry = _get_backend().get_entry(key) or {}
    return CredentialEvent(
        event_id=str(uuid4()),
        key=key,
        action=action,
        status=SecretStatus(entry.get("status", SecretStatus.ACTIVE)),
        tenant_id=entry.get("tenant_id", ""),
    )

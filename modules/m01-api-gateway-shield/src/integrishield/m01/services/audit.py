"""
M01 — Audit Logger
-------------------
Writes every intercepted RFC call to the Postgres audit_events table.

Design decisions:
- Synchronous write (not async) — keeps code simple for POC.
  At POC scale (~hundreds of events/hour) sync is fine.
  Post-funding: switch to async SQLAlchemy 2.x sessions.

- Session is opened and closed per write — no long-lived session
  held across requests.  Avoids connection-leak bugs.

- If the DB is unavailable the write fails silently (caller catches
  the exception and logs a warning).  M01 never drops the Redis event
  because of a DB failure.

Owned by Dev 1.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from shared.db.session import SessionLocal
from shared.db.models import AuditEvent
from shared.telemetry import get_logger
from integrishield.m01.models.rfc_request import DetectionFlags

logger = get_logger(__name__)


def write_audit_event(
    event_id: str,
    payload: dict[str, Any],
    flags: DetectionFlags,
) -> None:
    """
    Persist one AuditEvent row from an intercepted RFC call.

    Parameters
    ----------
    event_id : str
        UUID that also appears in the Redis Stream entry (for correlation).
    payload  : dict
        The api_call_event dict (same one published to Redis).
    flags    : DetectionFlags
        Output of run_detectors() — sets the is_* boolean columns.

    Raises
    ------
    sqlalchemy.exc.SQLAlchemyError
        On any DB failure — caller is responsible for logging/handling.
    """
    ts_raw = payload.get("timestamp")
    if isinstance(ts_raw, str):
        # ISO 8601 string → datetime (handles "Z" suffix)
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    elif isinstance(ts_raw, datetime):
        ts = ts_raw
    else:
        ts = datetime.now(tz=timezone.utc)

    row = AuditEvent(
        id=uuid.UUID(event_id),
        rfc_function=payload["rfc_function"],
        client_ip=payload.get("client_ip", "0.0.0.0"),
        user_id=payload["user_id"],
        timestamp=ts,
        rows_returned=payload.get("rows_returned", 0),
        response_time_ms=payload.get("response_time_ms", 0),
        status=payload.get("status", "SUCCESS"),
        sap_system=payload.get("sap_system"),
        is_off_hours=flags.is_off_hours,
        is_bulk_extraction=flags.is_bulk_extraction,
        is_shadow_endpoint=flags.is_shadow_endpoint,
        raw_payload=json.dumps(payload),
    )

    with SessionLocal() as db:
        db.add(row)
        db.commit()

    logger.info(
        "Audit event written",
        extra={
            "svc":      "m01",
            "event_id": event_id,
            "flags": {
                "off_hours":   flags.is_off_hours,
                "bulk":        flags.is_bulk_extraction,
                "shadow":      flags.is_shadow_endpoint,
            },
        },
    )

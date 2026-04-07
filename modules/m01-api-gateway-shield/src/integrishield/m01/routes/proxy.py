"""
M01 — POST /rfc/proxy
----------------------
The core route.  Every SAP RFC call flows through here.

Request lifecycle:
  1. Validate request body (Pydantic)
  2. Auth check (X-API-Key header via Depends)
  3. Forward to SAP backend (httpx) — capture rows_returned + response_time_ms
  4. Run detectors  (off-hours / bulk extraction / shadow endpoint)
  5. Publish api_call_event to Redis Streams  → rfc_events
  6. Write AuditEvent row to Postgres
  7. Return RFCProxyResponse to caller

If the SAP backend is unreachable the call is still recorded and
published — status="ERROR".  M01 never silently drops events.

Owned by Dev 1.
"""

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from shared.auth import require_api_key
from shared.telemetry import get_logger

from integrishield.m01.models.rfc_request import (
    DetectionFlags,
    RFCProxyRequest,
    RFCProxyResponse,
)
from integrishield.m01.services.detectors import run_detectors
from integrishield.m01.services.publisher import publish_rfc_event
from integrishield.m01.services.audit import write_audit_event

logger = get_logger(__name__)
router = APIRouter(tags=["rfc-proxy"])

_SAP_BACKEND_URL = os.getenv("SAP_BACKEND_URL", "http://mock-sap:8080")
_HTTP_TIMEOUT = float(os.getenv("SAP_TIMEOUT_S", "10"))


async def _call_sap_backend(
    rfc_function: str,
    parameters: dict,
) -> tuple[dict, int, str]:
    """
    Forward the RFC call to the SAP backend (or mock-sap in POC).

    Returns (sap_response_body, rows_returned, status_str).
    """
    url = f"{_SAP_BACKEND_URL}/rfc/{rfc_function}"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            t0 = time.monotonic()
            resp = await client.post(url, json=parameters)
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            resp.raise_for_status()
            body = resp.json()
            rows = body.get("rows_returned", 0)
            return body, rows, elapsed_ms, "SUCCESS"
    except httpx.TimeoutException:
        logger.warning("SAP backend timeout", extra={"svc": "m01", "fn": rfc_function})
        return {}, 0, int(_HTTP_TIMEOUT * 1000), "TIMEOUT"
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "SAP backend HTTP error",
            extra={"svc": "m01", "fn": rfc_function, "code": exc.response.status_code},
        )
        return {}, 0, 0, "ERROR"
    except httpx.RequestError as exc:
        logger.warning(
            "SAP backend unreachable",
            extra={"svc": "m01", "fn": rfc_function, "err": str(exc)},
        )
        return {}, 0, 0, "ERROR"


@router.post(
    "/proxy",
    response_model=RFCProxyResponse,
    summary="Proxy an SAP RFC call through IntegriShield",
)
async def rfc_proxy(
    body: RFCProxyRequest,
    request: Request,
    _key: Annotated[str, Depends(require_api_key)],
) -> RFCProxyResponse:
    """
    Transparent proxy for SAP RFC calls.

    - Forwards to SAP backend
    - Publishes api_call_event to rfc_events Redis stream
    - Writes to Postgres audit log
    - Returns SAP response + detection flags to caller
    """
    event_id   = str(uuid.uuid4())
    timestamp  = datetime.now(tz=timezone.utc)
    client_ip  = request.client.host if request.client else "0.0.0.0"

    # ── 1. Forward to SAP backend ──────────────────────────────────────────
    sap_body, rows_returned, response_time_ms, call_status = await _call_sap_backend(
        body.rfc_function, body.parameters
    )

    logger.info(
        "RFC call intercepted",
        extra={
            "svc":    "m01",
            "event":  event_id,
            "fn":     body.rfc_function,
            "user":   body.user_id,
            "rows":   rows_returned,
            "status": call_status,
        },
    )

    # ── 2. Run detectors ───────────────────────────────────────────────────
    flags: DetectionFlags = run_detectors(
        rfc_function=body.rfc_function,
        rows_returned=rows_returned,
        timestamp=timestamp,
    )

    if flags.is_off_hours:
        logger.warning(
            "Off-hours RFC call detected",
            extra={"svc": "m01", "user": body.user_id, "fn": body.rfc_function},
        )
    if flags.is_bulk_extraction:
        logger.warning(
            "Bulk extraction detected",
            extra={"svc": "m01", "user": body.user_id, "rows": rows_returned},
        )
    if flags.is_shadow_endpoint:
        logger.warning(
            "Shadow endpoint detected",
            extra={"svc": "m01", "fn": body.rfc_function, "user": body.user_id},
        )

    # ── 3. Publish to Redis Streams ─────────────────────────────────────────
    event_payload = {
        "event_id":        event_id,
        "rfc_function":    body.rfc_function,
        "client_ip":       client_ip,
        "user_id":         body.user_id,
        "timestamp":       timestamp.isoformat().replace("+00:00", "Z"),
        "rows_returned":   rows_returned,
        "response_time_ms": response_time_ms,
        "status":          call_status,
        "sap_system":      body.sap_system,
    }
    try:
        publish_rfc_event(event_payload)
    except Exception as exc:
        # Log but don't fail the proxy — Redis being down shouldn't
        # break the caller's RFC request.
        logger.warning(
            "Redis publish failed",
            extra={"svc": "m01", "err": str(exc), "event": event_id},
        )

    # ── 4. Write audit row ─────────────────────────────────────────────────
    try:
        write_audit_event(
            event_id=event_id,
            payload=event_payload,
            flags=flags,
        )
    except Exception as exc:
        logger.warning(
            "Audit DB write failed",
            extra={"svc": "m01", "err": str(exc), "event": event_id},
        )

    # ── 5. Return to caller ────────────────────────────────────────────────
    return RFCProxyResponse(
        event_id=event_id,
        rfc_function=body.rfc_function,
        status=call_status,
        rows_returned=rows_returned,
        response_time_ms=response_time_ms,
        sap_response=sap_body,
        is_off_hours=flags.is_off_hours,
        is_bulk_extraction=flags.is_bulk_extraction,
        is_shadow_endpoint=flags.is_shadow_endpoint,
    )

"""
M14 — Webhook routes  [POC STUB]

POST /webhooks/deliver  → stub: accepts payload, logs it, returns 202.
GET  /webhooks/status   → stub: returns empty delivery queue.

These routes exist so Dev 4's dashboard can wire up the webhook
delivery panel without waiting for M14's full implementation.
The contract (request/response shape) is final even in stub form.
"""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["webhooks"])


class WebhookDeliveryRequest(BaseModel):
    """
    Payload that any IntegriShield module sends to trigger an outbound webhook.
    Full M14 will fan this out to all configured destinations.
    """
    event_type: str          # e.g. "anomaly_event", "shadow_alert", "dlp_alert"
    event_id:   str          # correlates back to the Redis Stream entry
    payload:    dict[str, Any]
    destinations: list[str] = []   # override; empty = use configured defaults


class WebhookDeliveryResponse(BaseModel):
    accepted:   bool
    delivery_id: str | None
    note:       str


class WebhookStatusResponse(BaseModel):
    pending:    int
    delivered:  int
    failed:     int
    note:       str


@router.post("/deliver", response_model=WebhookDeliveryResponse, status_code=202)
async def deliver(body: WebhookDeliveryRequest) -> WebhookDeliveryResponse:
    """
    [STUB] Accept a webhook delivery request.
    Full M14 will enqueue this to Redis and fan out to destinations.
    """
    return WebhookDeliveryResponse(
        accepted=True,
        delivery_id=None,
        note="POC stub — delivery queuing not yet implemented",
    )


@router.get("/status", response_model=WebhookStatusResponse)
async def status() -> WebhookStatusResponse:
    """[STUB] Return delivery queue statistics."""
    return WebhookStatusResponse(
        pending=0,
        delivered=0,
        failed=0,
        note="POC stub — no delivery tracking yet",
    )

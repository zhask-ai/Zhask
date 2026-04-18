"""Webhook subscription CRUD and delivery inspection routes for M14."""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, Request

from integrishield.m14.db import WebhookDB
from integrishield.m14.models import DeliveryRecord, Subscription, SubscriptionCreate

router = APIRouter(tags=["webhooks"])


def _db(request: Request) -> WebhookDB:
    return request.app.state.db


def _dispatcher(request: Request):
    return request.app.state.dispatcher


# ---------------------------------------------------------------------------
# Subscription management
# ---------------------------------------------------------------------------

@router.post("", response_model=Subscription, status_code=201)
async def create_subscription(body: SubscriptionCreate, request: Request):
    """Register a new webhook destination."""
    return _db(request).create_subscription(
        url=body.url,
        secret=body.secret,
        event_filter=body.event_filter,
    )


@router.get("", response_model=list[Subscription])
async def list_subscriptions(request: Request, include_inactive: bool = False):
    """List webhook subscriptions."""
    return _db(request).list_subscriptions(active_only=not include_inactive)


@router.delete("/{sub_id}", status_code=204)
async def deactivate_subscription(sub_id: str, request: Request):
    """Deactivate a webhook subscription (soft-delete; delivery history preserved)."""
    ok = _db(request).deactivate_subscription(sub_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Subscription '{sub_id}' not found")


# ---------------------------------------------------------------------------
# Delivery inspection
# ---------------------------------------------------------------------------

@router.get("/{sub_id}/deliveries", response_model=list[DeliveryRecord])
async def get_deliveries(sub_id: str, request: Request, limit: int = 50):
    """Inspect delivery log for a subscription."""
    sub = _db(request).get_subscription(sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail=f"Subscription '{sub_id}' not found")
    return _db(request).list_deliveries(sub_id, limit=limit)


@router.post("/{sub_id}/replay", status_code=202)
async def replay_last_delivery(sub_id: str, request: Request):
    """Re-dispatch the most recent delivery for a subscription."""
    db = _db(request)
    sub = db.get_subscription(sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail=f"Subscription '{sub_id}' not found")

    latest = db.get_latest_delivery(sub_id)
    if latest is None:
        raise HTTPException(status_code=404, detail="No deliveries found for this subscription")

    payload = db.get_delivery_payload(latest.id)
    asyncio.create_task(
        _dispatcher(request).dispatch(latest.event_id, latest.event_type, payload)
    )
    return {"replaying": latest.id, "event_type": latest.event_type}


# ---------------------------------------------------------------------------
# Test endpoint
# ---------------------------------------------------------------------------

@router.post("/test", status_code=202)
async def test_delivery(request: Request):
    """Send a synthetic test event to all active subscriptions."""
    event_id = str(uuid.uuid4())
    payload = {
        "event_type": "test",
        "event_id": event_id,
        "message": "IntegriShield test delivery",
    }
    asyncio.create_task(_dispatcher(request).dispatch(event_id, "test", payload))
    return {"event_id": event_id, "note": "Test event dispatched to all active subscriptions"}

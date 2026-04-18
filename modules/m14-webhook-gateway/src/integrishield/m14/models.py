"""Pydantic models for M14 Webhook Gateway."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    DLQ = "dlq"


class SubscriptionCreate(BaseModel):
    url: str
    secret: str = ""  # HMAC signing secret; empty = no signature header
    event_filter: list[str] = Field(
        default_factory=list,
        description="Event types to receive; empty list = all events.",
    )


class Subscription(BaseModel):
    id: str
    url: str
    event_filter: list[str]
    active: bool = True
    created_at: datetime


class DeliveryRecord(BaseModel):
    id: str
    subscription_id: str
    event_id: str
    event_type: str
    status: DeliveryStatus
    attempt_count: int = 0
    last_attempt_at: datetime | None = None
    delivered_at: datetime | None = None
    error_message: str = ""


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    backend: str


class WebhookStatsResponse(BaseModel):
    subscriptions_active: int
    deliveries_pending: int
    deliveries_delivered: int
    deliveries_failed: int
    deliveries_dlq: int

"""Fan-out dispatcher for M14 Webhook Gateway.

Reads from the WebhookDB subscriber registry, signs each payload with HMAC,
POSTs to each matching subscription URL with retry, and writes DLQ entries
on final failure.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import redis as redis_lib

from integrishield.m14.db import WebhookDB
from integrishield.m14.models import DeliveryStatus
from integrishield.m14.services.retry import MAX_ATTEMPTS, with_retry
from integrishield.m14.services.signer import signature_header

logger = logging.getLogger(__name__)

DLQ_STREAM = "integrishield:webhook_dlq"
DLQ_MAXLEN = 10_000


class Dispatcher:
    """Async fan-out dispatcher. Call dispatch() for each incoming event."""

    def __init__(self, db: WebhookDB, redis_url: str) -> None:
        self._db = db
        self._redis_url = redis_url
        self._redis: redis_lib.Redis | None = None

    def connect_redis(self) -> None:
        try:
            r = redis_lib.Redis.from_url(self._redis_url, decode_responses=True)
            r.ping()
            self._redis = r
            logger.info("m14 dispatcher connected to Redis")
        except Exception as exc:
            logger.warning("m14 Redis unavailable — DLQ disabled: %s", exc)

    async def dispatch(self, event_id: str, event_type: str, payload: dict[str, Any]) -> None:
        """Fan out one event to all matching active subscriptions."""
        subscriptions = self._db.list_subscriptions(active_only=True)
        matching = [
            s for s in subscriptions
            if not s.event_filter or event_type in s.event_filter
        ]

        if not matching:
            return

        tasks = [
            self._deliver_to(sub.id, event_id, event_type, payload)
            for sub in matching
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _deliver_to(
        self,
        sub_id: str,
        event_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        import httpx  # noqa: PLC0415

        delivery = self._db.create_delivery(sub_id, event_id, event_type, payload)
        sub = self._db.get_subscription(sub_id)
        if sub is None:
            return

        secret = self._db.get_subscription_secret(sub_id)
        headers = {"Content-Type": "application/json", **signature_header(payload, secret)}
        body = json.dumps(payload)

        async def attempt() -> None:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(sub.url, content=body, headers=headers)
                resp.raise_for_status()

        result, attempts, error = await with_retry(
            attempt, max_attempts=MAX_ATTEMPTS, label=f"delivery {delivery.id}"
        )

        if result is None:
            final_status = DeliveryStatus.DLQ if attempts >= MAX_ATTEMPTS else DeliveryStatus.FAILED
            self._db.update_delivery(delivery.id, final_status, attempts, error)
            self._write_dlq(event_id, event_type, sub_id, delivery.id, error, payload)
        else:
            self._db.update_delivery(delivery.id, DeliveryStatus.DELIVERED, attempts)

    def _write_dlq(
        self,
        event_id: str,
        event_type: str,
        sub_id: str,
        delivery_id: str,
        error: str,
        payload: dict[str, Any],
    ) -> None:
        if self._redis is None:
            return
        try:
            self._redis.xadd(
                DLQ_STREAM,
                {
                    "event_id": event_id,
                    "event_type": event_type,
                    "subscription_id": sub_id,
                    "delivery_id": delivery_id,
                    "error": error[:500],
                    "payload": json.dumps(payload)[:4000],
                },
                maxlen=DLQ_MAXLEN,
                approximate=True,
            )
        except Exception:
            logger.exception("Failed to write DLQ entry for delivery %s", delivery_id)

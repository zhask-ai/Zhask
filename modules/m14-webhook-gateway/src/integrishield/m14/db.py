"""SQLite persistence for M14 Webhook Gateway — subscriptions and delivery log."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from integrishield.m14.models import DeliveryRecord, DeliveryStatus, Subscription

_CREATE = """
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id           TEXT PRIMARY KEY,
    url          TEXT NOT NULL,
    secret       TEXT NOT NULL DEFAULT '',
    event_filter TEXT NOT NULL DEFAULT '[]',
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               TEXT PRIMARY KEY,
    subscription_id  TEXT NOT NULL,
    event_id         TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    payload          TEXT NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending',
    attempt_count    INTEGER NOT NULL DEFAULT 0,
    last_attempt_at  TEXT,
    delivered_at     TEXT,
    error_message    TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (subscription_id) REFERENCES webhook_subscriptions(id)
);

CREATE INDEX IF NOT EXISTS idx_del_sub ON webhook_deliveries (subscription_id);
CREATE INDEX IF NOT EXISTS idx_del_status ON webhook_deliveries (status);
"""


class WebhookDB:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._lock = Lock()
        with self._connect() as conn:
            conn.executescript(_CREATE)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def create_subscription(self, url: str, secret: str, event_filter: list[str]) -> Subscription:
        sub_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO webhook_subscriptions (id, url, secret, event_filter, active, created_at) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (sub_id, url, secret, json.dumps(event_filter), now),
            )
        return Subscription(
            id=sub_id,
            url=url,
            event_filter=event_filter,
            active=True,
            created_at=datetime.fromisoformat(now),
        )

    def list_subscriptions(self, active_only: bool = True) -> list[Subscription]:
        with self._lock, self._connect() as conn:
            if active_only:
                rows = conn.execute(
                    "SELECT * FROM webhook_subscriptions WHERE active = 1"
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM webhook_subscriptions").fetchall()
        return [self._row_to_sub(r) for r in rows]

    def get_subscription(self, sub_id: str) -> Subscription | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_subscriptions WHERE id = ?", (sub_id,)
            ).fetchone()
        return self._row_to_sub(row) if row else None

    def get_subscription_secret(self, sub_id: str) -> str:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT secret FROM webhook_subscriptions WHERE id = ?", (sub_id,)
            ).fetchone()
        return row["secret"] if row else ""

    def deactivate_subscription(self, sub_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE webhook_subscriptions SET active = 0 WHERE id = ?", (sub_id,)
            )
        return cur.rowcount > 0

    @staticmethod
    def _row_to_sub(row: sqlite3.Row) -> Subscription:
        return Subscription(
            id=row["id"],
            url=row["url"],
            event_filter=json.loads(row["event_filter"]),
            active=bool(row["active"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Deliveries
    # ------------------------------------------------------------------

    def create_delivery(
        self,
        subscription_id: str,
        event_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> DeliveryRecord:
        del_id = str(uuid.uuid4())
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO webhook_deliveries "
                "(id, subscription_id, event_id, event_type, payload, status) "
                "VALUES (?, ?, ?, ?, ?, 'pending')",
                (del_id, subscription_id, event_id, event_type, json.dumps(payload)),
            )
        return DeliveryRecord(
            id=del_id,
            subscription_id=subscription_id,
            event_id=event_id,
            event_type=event_type,
            status=DeliveryStatus.PENDING,
        )

    def update_delivery(
        self,
        delivery_id: str,
        status: DeliveryStatus,
        attempt_count: int,
        error_message: str = "",
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        delivered_at = now if status == DeliveryStatus.DELIVERED else None
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE webhook_deliveries SET status=?, attempt_count=?, "
                "last_attempt_at=?, delivered_at=?, error_message=? WHERE id=?",
                (status.value, attempt_count, now, delivered_at, error_message, delivery_id),
            )

    def get_delivery(self, delivery_id: str) -> DeliveryRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE id = ?", (delivery_id,)
            ).fetchone()
        return self._row_to_delivery(row) if row else None

    def list_deliveries(self, subscription_id: str, limit: int = 50) -> list[DeliveryRecord]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE subscription_id = ? "
                "ORDER BY rowid DESC LIMIT ?",
                (subscription_id, limit),
            ).fetchall()
        return [self._row_to_delivery(r) for r in rows]

    def get_latest_delivery(self, subscription_id: str) -> DeliveryRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE subscription_id = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (subscription_id,),
            ).fetchone()
        return self._row_to_delivery(row) if row else None

    def get_delivery_payload(self, delivery_id: str) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM webhook_deliveries WHERE id = ?", (delivery_id,)
            ).fetchone()
        return json.loads(row["payload"]) if row else {}

    def stats(self) -> dict[str, int]:
        with self._lock, self._connect() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM webhook_subscriptions WHERE active = 1"
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM webhook_deliveries GROUP BY status"
            ).fetchall()
        counts = {r["status"]: r["cnt"] for r in rows}
        return {
            "subscriptions_active": active,
            "deliveries_pending": counts.get("pending", 0),
            "deliveries_delivered": counts.get("delivered", 0),
            "deliveries_failed": counts.get("failed", 0),
            "deliveries_dlq": counts.get("dlq", 0),
        }

    @staticmethod
    def _row_to_delivery(row: sqlite3.Row) -> DeliveryRecord:
        return DeliveryRecord(
            id=row["id"],
            subscription_id=row["subscription_id"],
            event_id=row["event_id"],
            event_type=row["event_type"],
            status=DeliveryStatus(row["status"]),
            attempt_count=row["attempt_count"],
            last_attempt_at=(
                datetime.fromisoformat(row["last_attempt_at"])
                if row["last_attempt_at"]
                else None
            ),
            delivered_at=(
                datetime.fromisoformat(row["delivered_at"]) if row["delivered_at"] else None
            ),
            error_message=row["error_message"] or "",
        )

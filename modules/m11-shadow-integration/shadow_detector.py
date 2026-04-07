"""
Shadow endpoint detection logic for M11.

Tracks which RFC functions have been seen. Any function NOT in the
allowlist triggers a shadow alert. Also tracks how many times an
unknown function has been called today for severity escalation.
"""

import logging
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from shared.event_bus.producer import RedisStreamProducer

logger = logging.getLogger(__name__)


def _today_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class ShadowDetector:
    def __init__(
        self,
        known_endpoints: frozenset[str],
        redis_url: str,
        output_stream: str,
    ):
        self._known = known_endpoints
        self._producer = RedisStreamProducer(redis_url, output_stream)
        # Track daily call counts for unknown functions: date → {fn: count}
        self._daily_counts: dict[str, Counter] = defaultdict(Counter)

    def process(self, event_id: str, data: dict[str, Any]) -> Optional[dict]:
        rfc_fn = data.get("rfc_function", "")

        if rfc_fn in self._known:
            return None  # known endpoint — no alert

        today = _today_key()
        self._daily_counts[today][rfc_fn] += 1
        times_seen = self._daily_counts[today][rfc_fn]
        first_seen = times_seen == 1

        severity = "CRITICAL" if first_seen else "HIGH" if times_seen < 5 else "MEDIUM"

        alert = {
            "alert_id": str(uuid.uuid4()),
            "original_event_id": data.get("event_id", ""),
            "rfc_function": rfc_fn,
            "client_ip": data.get("client_ip", ""),
            "user_id": data.get("user_id", ""),
            "timestamp": data.get("timestamp", ""),
            "first_seen": first_seen,
            "times_seen_today": times_seen,
            "severity": severity,
        }

        logger.warning(
            "SHADOW ENDPOINT | fn=%s first_seen=%s times_today=%d client=%s",
            rfc_fn,
            first_seen,
            times_seen,
            data.get("client_ip"),
        )
        self._producer.publish(alert)
        return alert

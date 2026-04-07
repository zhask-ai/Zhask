"""
Traffic analyzer: enriches raw RFC events with ML features.
Reads from `rfc_events`, publishes enriched events to `analyzed_events`.
"""

import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml.training.feature_engineering import (
    SlidingWindowState,
    hour_of_day,
    is_known_endpoint,
    is_off_hours,
    is_weekend,
    parse_timestamp,
    rows_per_second,
)
from shared.event_bus.producer import RedisStreamProducer

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """
    Stateful feature extractor.
    Maintains sliding windows across events and enriches each event with features.
    """

    def __init__(self, redis_url: str, output_stream: str):
        self._state = SlidingWindowState()
        self._producer = RedisStreamProducer(redis_url, output_stream)

    def process(self, event_id: str, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Extract features from a raw RFC event and publish the enriched event.
        Returns the enriched event dict.
        """
        try:
            ts = parse_timestamp(raw["timestamp"])
        except (KeyError, ValueError):
            logger.warning("Event %s has invalid timestamp, skipping", event_id)
            return {}

        client_ip = raw.get("client_ip", "unknown")
        rfc_fn = raw.get("rfc_function", "UNKNOWN")
        rows = int(raw.get("rows_returned", 0))
        rt_ms = int(raw.get("response_time_ms", 1))

        # Update window state
        self._state.add(ts, client_ip, rfc_fn)

        enriched = {
            # Pass-through original fields
            "event_id": raw.get("event_id", str(uuid.uuid4())),
            "rfc_function": rfc_fn,
            "client_ip": client_ip,
            "user_id": raw.get("user_id", "unknown"),
            "timestamp": raw.get("timestamp", ""),
            "rows_returned": rows,
            "response_time_ms": rt_ms,
            "status": raw.get("status", "UNKNOWN"),
            "sap_system": raw.get("sap_system", ""),
            # Computed features
            "hour_of_day": hour_of_day(ts),
            "is_off_hours": is_off_hours(ts),
            "is_weekend": is_weekend(ts),
            "rows_per_second": rows_per_second(rows, rt_ms),
            "client_req_count_5m": self._state.client_req_count_5m(client_ip),
            "unique_functions_10m": self._state.unique_functions_10m(),
            "endpoint_entropy_10m": round(self._state.endpoint_entropy_10m(), 4),
            "is_known_endpoint": is_known_endpoint(rfc_fn),
        }

        self._producer.publish(enriched)
        logger.debug(
            "Analyzed event %s: off_hours=%s rows=%d known=%s",
            enriched["event_id"],
            bool(enriched["is_off_hours"]),
            rows,
            bool(enriched["is_known_endpoint"]),
        )
        return enriched

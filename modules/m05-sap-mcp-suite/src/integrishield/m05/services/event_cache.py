"""In-memory ring-buffer event cache for M05 SAP MCP Suite."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any


class EventCache:
    """Thread-safe per-stream ring buffers.

    Each stream gets a deque of fixed max size. Events are plain dicts.
    """

    # Canonical stream → friendly key mapping
    STREAM_KEYS = {
        "integrishield:api_call_events": "api_call_events",
        "integrishield:anomaly_events": "anomaly_events",
        "integrishield:dlp_alerts": "dlp_alerts",
        "integrishield:alert_events": "alert_events",
    }

    def __init__(self, max_size: int = 1000) -> None:
        self._buffers: dict[str, deque] = {
            key: deque(maxlen=max_size) for key in self.STREAM_KEYS.values()
        }
        self._lock = asyncio.Lock()

    def push(self, stream_name: str, event: dict[str, Any]) -> None:
        """Append an event to the appropriate buffer (non-async, called from thread)."""
        key = self.STREAM_KEYS.get(stream_name)
        if key and key in self._buffers:
            self._buffers[key].append(event)

    def get_recent(
        self,
        stream_key: str,
        limit: int = 50,
        since_minutes: int = 0,
    ) -> list[dict[str, Any]]:
        """Return most recent events from a buffer, optionally filtered by time."""
        buf = self._buffers.get(stream_key, deque())
        items = list(buf)
        items.reverse()  # newest first

        if since_minutes > 0:
            cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=since_minutes)
            filtered = []
            for item in items:
                ts_str = item.get("timestamp_utc") or item.get("timestamp") or ""
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts >= cutoff:
                        filtered.append(item)
                except Exception:
                    filtered.append(item)  # include if we can't parse timestamp
            items = filtered

        return items[:limit]

    def stats(self) -> dict[str, int]:
        return {key: len(buf) for key, buf in self._buffers.items()}

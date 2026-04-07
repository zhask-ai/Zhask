"""Redis Streams consumer for M05 SAP MCP Suite — feeds EventCache."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

# Allow running as standalone and as installed package
sys.path.insert(0, str(Path(__file__).resolve().parents[8] / "shared"))

try:
    from shared.event_bus.consumer import RedisStreamConsumer
except ImportError:
    # Fallback minimal base class for environments without shared/ on path
    from integrishield.m05.services._consumer_base import RedisStreamConsumer  # type: ignore

from integrishield.m05.services.event_cache import EventCache

logger = logging.getLogger(__name__)


class SapMcpConsumer(RedisStreamConsumer):
    """Consumes events from a Redis Stream and pushes them into EventCache."""

    def __init__(
        self,
        redis_url: str,
        stream_name: str,
        consumer_name: str,
        group_name: str,
        cache: EventCache,
    ) -> None:
        super().__init__(
            redis_url=redis_url,
            stream_name=stream_name,
            consumer_name=consumer_name,
            group_name=group_name,
        )
        self._cache = cache
        self._stream_name = stream_name

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        self._cache.push(self._stream_name, data)
        logger.debug("m05 cached event %s from %s", event_id, self._stream_name)

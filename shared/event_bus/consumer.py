"""
Redis Streams consumer base class.
Owned by Dev 1 (shared/). Dev 2 uses this as-is.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import redis

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "ml_consumers"
BATCH_SIZE = 100
BLOCK_MS = 1000  # block for 1s waiting for new messages


class RedisStreamConsumer(ABC):
    """
    Base class for consuming events from a Redis Stream.

    Subclass this and implement `handle_event(event_id, data)`.
    Call `run()` to start the blocking consumer loop.
    """

    def __init__(
        self,
        redis_url: str,
        stream_name: str,
        consumer_name: str,
        group_name: str = CONSUMER_GROUP,
    ):
        self.stream_name = stream_name
        self.consumer_name = consumer_name
        self.group_name = group_name
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self._running = False

    def _ensure_group(self) -> None:
        """Create consumer group if it doesn't exist."""
        try:
            self.redis.xgroup_create(
                self.stream_name, self.group_name, id="0", mkstream=True
            )
            logger.info(
                "Created consumer group '%s' on stream '%s'",
                self.group_name,
                self.stream_name,
            )
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                pass  # group already exists, that's fine
            else:
                raise

    @abstractmethod
    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        """Process a single event. Override in subclasses."""

    def run(self) -> None:
        """Start the blocking consumer loop."""
        self._ensure_group()
        self._running = True
        logger.info(
            "Consumer '%s' listening on stream '%s'",
            self.consumer_name,
            self.stream_name,
        )
        while self._running:
            try:
                messages = self.redis.xreadgroup(
                    groupname=self.group_name,
                    consumername=self.consumer_name,
                    streams={self.stream_name: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )
                if not messages:
                    continue

                for _stream, event_list in messages:
                    for event_id, raw in event_list:
                        try:
                            # Values are stored as strings; deserialise nested JSON if needed
                            data = {
                                k: self._try_parse(v) for k, v in raw.items()
                            }
                            self.handle_event(event_id, data)
                            self.redis.xack(
                                self.stream_name, self.group_name, event_id
                            )
                        except Exception:
                            logger.exception(
                                "Error handling event %s — leaving unacked for retry",
                                event_id,
                            )
            except redis.ConnectionError:
                logger.warning("Redis connection lost, retrying in 3s…")
                time.sleep(3)

    def stop(self) -> None:
        self._running = False

    @staticmethod
    def _try_parse(value: str) -> Any:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

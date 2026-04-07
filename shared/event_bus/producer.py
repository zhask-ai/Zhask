"""
Redis Streams producer base class.
Owned by Dev 1 (shared/). Dev 2 uses this as-is.
"""

import json
import logging
from typing import Any

import redis

logger = logging.getLogger(__name__)

MAX_STREAM_LEN = 10_000  # keep streams bounded during POC


class RedisStreamProducer:
    """
    Publishes events to a Redis Stream.

    Usage:
        producer = RedisStreamProducer(redis_url, "anomaly_events")
        producer.publish({"anomaly_score": -0.8, "severity": "CRITICAL"})
    """

    def __init__(self, redis_url: str, stream_name: str):
        self.stream_name = stream_name
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def publish(self, data: dict[str, Any]) -> str:
        """
        Publish a single event. Returns the Redis stream entry ID.
        All values are JSON-serialised so complex types survive the round-trip.
        """
        serialised = {k: self._serialise(v) for k, v in data.items()}
        event_id = self.redis.xadd(
            self.stream_name,
            serialised,
            maxlen=MAX_STREAM_LEN,
            approximate=True,
        )
        logger.debug("Published event %s to stream '%s'", event_id, self.stream_name)
        return event_id

    @staticmethod
    def _serialise(value: Any) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(value)

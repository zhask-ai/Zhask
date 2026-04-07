"""
M01 — Event Publisher
----------------------
Wraps shared.event_bus.RedisStreamProducer to publish validated
api_call_event records to the rfc_events Redis Stream.

Why the validation step?
  M03, M08, M11 all consume rfc_events.  If M01 publishes a malformed
  event it silently breaks three other modules' processing loops.
  Validating at the producer (fail fast) is much cheaper to debug.

Owned by Dev 1.
"""

import os
from functools import lru_cache
from typing import Any

from shared.event_bus.producer import RedisStreamProducer
from shared.utils.schema_validator import validate_event
from shared.telemetry import get_logger

logger = get_logger(__name__)

_STREAM_NAME  = "rfc_events"
_REDIS_URL    = os.getenv("REDIS_URL", "redis://redis:6379")


@lru_cache(maxsize=1)
def _get_producer() -> RedisStreamProducer:
    """
    Return the singleton RedisStreamProducer for rfc_events.
    Created once on first call, reused for all subsequent calls.
    lru_cache is safe here — RedisStreamProducer is thread-safe.
    """
    logger.info(
        "Creating RedisStreamProducer",
        extra={"svc": "m01", "stream": _STREAM_NAME, "redis": _REDIS_URL},
    )
    return RedisStreamProducer(redis_url=_REDIS_URL, stream_name=_STREAM_NAME)


def publish_rfc_event(event: dict[str, Any]) -> str:
    """
    Validate *event* against the api_call_event JSON schema, then
    publish it to the rfc_events Redis Stream.

    Parameters
    ----------
    event : dict
        Must conform to shared/schemas/v1/api_call_event.json.

    Returns
    -------
    str
        The Redis stream entry ID (e.g. "1712534400000-0").

    Raises
    ------
    jsonschema.ValidationError
        If the event doesn't match the schema.
    redis.RedisError
        If the publish fails (connection issue, OOM policy, etc.).
    """
    # Strip None values — api_call_event schema uses additionalProperties: false
    # so optional fields like sap_system must not be present if None.
    clean_event = {k: v for k, v in event.items() if v is not None}

    validate_event("api_call_event", clean_event)

    producer = _get_producer()
    entry_id = producer.publish(clean_event)

    logger.info(
        "api_call_event published",
        extra={
            "svc":      "m01",
            "stream":   _STREAM_NAME,
            "entry_id": entry_id,
            "event_id": clean_event.get("event_id"),
            "fn":       clean_event.get("rfc_function"),
        },
    )
    return entry_id

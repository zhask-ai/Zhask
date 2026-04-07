"""
shared.utils.schema_validator
------------------------------
Validates event dicts against the JSON schemas in shared/schemas/v1/.

M01 uses this before publishing to Redis Streams so malformed events
never enter the bus — fail fast at the producer, not somewhere downstream.

Owned by Dev 1.
"""

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import ValidationError

logger = logging.getLogger(__name__)

# Resolve schema directory relative to this file so the path works
# regardless of where the process is launched from.
_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "v1"

# Map of event type → schema filename
_SCHEMA_FILES: dict[str, str] = {
    "api_call_event":  "api_call_event.json",
    "analyzed_event":  "analyzed_event.json",
    "anomaly_event":   "anomaly_event.json",
    "shadow_alert":    "shadow_alert.json",
    "dlp_alert":       "dlp_alert.json",
}


@lru_cache(maxsize=None)
def _load_schema(schema_name: str) -> dict:
    """Load and cache a JSON schema by name."""
    path = _SCHEMA_DIR / schema_name
    if not path.exists():
        raise FileNotFoundError(f"Schema not found: {path}")
    with path.open() as fh:
        return json.load(fh)


def validate_event(event_type: str, data: dict[str, Any]) -> None:
    """
    Validate *data* against the schema for *event_type*.

    Raises
    ------
    KeyError
        If *event_type* is not a known schema name.
    jsonschema.ValidationError
        If *data* does not conform to the schema.

    Usage
    -----
    >>> validate_event("api_call_event", {"event_id": "...", ...})
    """
    filename = _SCHEMA_FILES.get(event_type)
    if filename is None:
        raise KeyError(
            f"Unknown event type '{event_type}'. "
            f"Known types: {list(_SCHEMA_FILES)}"
        )
    schema = _load_schema(filename)
    try:
        jsonschema.validate(instance=data, schema=schema)
    except ValidationError as exc:
        logger.warning(
            "Schema validation failed for '%s': %s", event_type, exc.message
        )
        raise


def is_valid_event(event_type: str, data: dict[str, Any]) -> bool:
    """
    Non-raising variant — returns True if valid, False otherwise.
    Useful for logging/metrics paths that should never crash the hot loop.
    """
    try:
        validate_event(event_type, data)
        return True
    except (KeyError, ValidationError):
        return False

"""
shared.telemetry.logger
------------------------
Structured JSON logging for IntegriShield.

Every module calls get_logger(__name__) instead of logging.getLogger().
The JSON format makes logs grep-able and Datadog/CloudWatch ingestible
without any pipeline transformation — important for the eventual SOC
dashboard integration (Dev 4's territory).

Format (one JSON object per line):
{
  "ts":      "2026-04-07T02:14:33.123456Z",
  "level":   "WARNING",
  "logger":  "modules.m01_api_gateway_shield.detectors",
  "msg":     "Off-hours RFC call detected",
  "module":  "m01",
  "extra":   { ... caller-supplied fields ... }
}

Owned by Dev 1.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any


class _JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        # Pull caller-supplied extra fields (everything that isn't a
        # standard LogRecord attribute).
        _STANDARD_ATTRS = {
            "args", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "message",
            "module", "msecs", "msg", "name", "pathname", "process",
            "processName", "relativeCreated", "stack_info", "thread",
            "threadName",
        }
        extra: dict[str, Any] = {
            k: v for k, v in record.__dict__.items()
            if k not in _STANDARD_ATTRS and not k.startswith("_")
        }

        payload: dict[str, Any] = {
            "ts":     datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
        }

        if extra:
            payload["extra"] = extra

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(level: str | None = None) -> None:
    """
    Call once at application startup (e.g. in main.py / __main__).

    Reads LOG_LEVEL from the environment if *level* is not provided.
    Defaults to INFO.
    """
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()

    root = logging.getLogger()
    root.setLevel(log_level)

    # Remove any handlers that Python or a framework may have added.
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())
    root.addHandler(handler)

    # Quiet noisy third-party loggers.
    for noisy in ("uvicorn.access", "httpx", "redis"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Return a module-level logger.

    Usage (top of every module file):
        from shared.telemetry import get_logger
        logger = get_logger(__name__)

    NOTE: Do NOT use 'module' as an extra key — it is a reserved LogRecord
    attribute and Python will raise KeyError.  Use 'svc' or 'mod' instead:
        logger.info("msg", extra={"svc": "m01", "rfc": "RFC_READ_TABLE"})
    """
    return logging.getLogger(name)

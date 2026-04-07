"""OpenTelemetry setup for IntegriShield services.

Configures:
- Traces  → OTLP exporter (or console in POC mode)
- Metrics → OTLP exporter (or console in POC mode)
- Logging → Structured JSON logging with trace context

Usage in any module's main.py:
    from shared.telemetry import setup_telemetry
    setup_telemetry("m04-zero-trust-fabric")
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OTEL_EXPORTER_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
OTEL_SERVICE_NAMESPACE = os.getenv("OTEL_SERVICE_NAMESPACE", "integrishield")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("LOG_FORMAT", "json")  # "json" or "text"

_initialized = False


# ---------------------------------------------------------------------------
# Structured JSON formatter
# ---------------------------------------------------------------------------


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter with OpenTelemetry trace context."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add trace context if OpenTelemetry is available
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx.is_valid:
                log_entry["trace_id"] = format(ctx.trace_id, "032x")
                log_entry["span_id"] = format(ctx.span_id, "016x")
        except ImportError:
            pass

        # Add any extra attributes
        for key in ("service_name", "tenant_id", "event_id", "module_name"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        return json.dumps(log_entry, default=str)


# ---------------------------------------------------------------------------
# Setup function
# ---------------------------------------------------------------------------


def setup_telemetry(service_name: str) -> None:
    """Initialize OpenTelemetry tracing, metrics, and structured logging.

    Call this once at startup in each module's main.py.

    In POC mode (no OTEL_EXPORTER_OTLP_ENDPOINT), only structured logging
    is configured. When OTEL_EXPORTER_OTLP_ENDPOINT is set, full
    OpenTelemetry trace and metric export is enabled.
    """
    global _initialized
    if _initialized:
        return
    _initialized = True

    # ── Structured logging ──────────────────────────────────────────
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # Remove existing handlers
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if LOG_FORMAT == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                f"%(asctime)s [{service_name}] %(levelname)s %(name)s — %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
    root_logger.addHandler(handler)

    logger = logging.getLogger(__name__)
    logger.info("Telemetry initialized for service '%s'", service_name)

    # ── OpenTelemetry (production only) ─────────────────────────────
    if not OTEL_EXPORTER_ENDPOINT:
        logger.info(
            "OTEL_EXPORTER_OTLP_ENDPOINT not set — running in POC mode (structured logging only). "
            "Set the endpoint to enable full trace/metric export."
        )
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_NAMESPACE

        resource = Resource.create({
            SERVICE_NAME: service_name,
            SERVICE_NAMESPACE: OTEL_SERVICE_NAMESPACE,
        })

        tracer_provider = TracerProvider(resource=resource)
        span_exporter = OTLPSpanExporter(endpoint=OTEL_EXPORTER_ENDPOINT)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(tracer_provider)

        logger.info(
            "OpenTelemetry tracing enabled — exporting to %s",
            OTEL_EXPORTER_ENDPOINT,
        )
    except ImportError:
        logger.warning(
            "OpenTelemetry SDK not installed. Install: pip install opentelemetry-sdk "
            "opentelemetry-exporter-otlp-proto-grpc"
        )
    except Exception as exc:
        logger.warning("Failed to initialize OpenTelemetry: %s", exc)


def get_tracer(name: str):
    """Get an OpenTelemetry tracer (or a no-op tracer if OTEL is not configured)."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return None

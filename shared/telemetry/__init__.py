"""IntegriShield — Shared Telemetry Package.

OpenTelemetry setup for traces, metrics, and structured logging.
Every module calls `setup_telemetry(service_name)` once at startup.
"""

from integrishield_telemetry.setup import setup_telemetry

__all__ = ["setup_telemetry"]

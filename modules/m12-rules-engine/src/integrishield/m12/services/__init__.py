"""Rules evaluation service — core detection logic for M12."""

from datetime import datetime, timezone

from integrishield.m12.config import settings
from integrishield.m12.models import Alert, ApiCallEvent, Scenario, Severity


def evaluate_event(event: ApiCallEvent | dict) -> Alert | None:
    """Evaluate a raw event against detection rules for the 3 POC scenarios.

    Returns an ``Alert`` if a rule matches, otherwise ``None``.
    """
    if isinstance(event, dict):
        bytes_out = int(event.get("bytes_out", 0))
        off_hours = bool(event.get("off_hours", False))
        unknown_endpoint = bool(event.get("unknown_endpoint", False))
        event_id = event.get("event_id")
    else:
        bytes_out = event.bytes_out
        off_hours = event.off_hours
        unknown_endpoint = event.unknown_endpoint
        event_id = event.event_id

    if bytes_out > settings.bulk_extraction_bytes:
        scenario = Scenario.BULK_EXTRACTION
        severity = Severity.CRITICAL
    elif off_hours:
        scenario = Scenario.OFF_HOURS_RFC
        severity = Severity.MEDIUM
    elif unknown_endpoint:
        scenario = Scenario.SHADOW_ENDPOINT
        severity = Severity.CRITICAL
    else:
        return None

    return Alert(
        event_id=event_id,
        scenario=scenario,
        severity=severity,
        message=alert_message(scenario),
        timestamp_utc=datetime.now(timezone.utc),
    )


def alert_message(scenario: Scenario | str) -> str:
    """Human-readable alert description."""
    messages = {
        Scenario.BULK_EXTRACTION: "Bulk data extraction detected in SAP access pattern",
        Scenario.OFF_HOURS_RFC: "Off-hours RFC call detected in SAP access pattern",
        Scenario.SHADOW_ENDPOINT: "Shadow endpoint detected in SAP access pattern",
    }
    if isinstance(scenario, str):
        for s in Scenario:
            if s.value == scenario:
                return messages.get(s, f"{scenario} detected in SAP access pattern")
    return messages.get(scenario, f"{scenario} detected in SAP access pattern")

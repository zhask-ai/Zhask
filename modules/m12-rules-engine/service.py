from datetime import datetime, timezone


def evaluate_event(event: dict) -> dict | None:
    bytes_out = int(event.get("bytes_out", 0))
    off_hours = bool(event.get("off_hours", False))
    unknown_endpoint = bool(event.get("unknown_endpoint", False))

    if bytes_out > 10_000_000:
        scenario = "bulk-extraction"
        severity = "critical"
    elif off_hours:
        scenario = "off-hours-rfc"
        severity = "medium"
    elif unknown_endpoint:
        scenario = "shadow-endpoint"
        severity = "critical"
    else:
        return None

    return {
        "event_id": event.get("event_id"),
        "scenario": scenario,
        "severity": severity,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_module": "m12-rules-engine",
    }


def alert_message(alert: dict) -> str:
    scenario = alert.get("scenario", "unknown")
    return f"{scenario} detected in SAP access pattern"

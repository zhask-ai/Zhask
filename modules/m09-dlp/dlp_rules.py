"""
Rule-based DLP engine for M09.

Three rules, checked in order:
  1. HIGH_ROW_COUNT   — rows_returned > threshold (absolute spike)
  2. BLOCKLISTED_FUNCTION — high-risk RFC function + elevated row count
  3. VELOCITY_SPIKE   — too many requests from one client in 5 minutes

Each rule returns a DLP alert dict or None.
"""

import uuid
from typing import Any, Optional

# SAP RFC functions with elevated data exfiltration risk
BLOCKLISTED_FUNCTIONS = frozenset(
    [
        "RFC_READ_TABLE",
        "BAPI_MATERIAL_GETLIST",
        "BAPI_CUSTOMER_GETLIST",
        "BAPI_SALESORDER_GETLIST",
        "BAPI_USER_GETLIST",
        "BAPI_VENDOR_GETLIST",
        "BAPI_EMPLOYEE_GETDATA",
    ]
)


def _build_alert(
    data: dict[str, Any],
    rule: str,
    threshold: int,
    severity: str,
) -> dict[str, Any]:
    return {
        "alert_id": str(uuid.uuid4()),
        "original_event_id": data.get("event_id", ""),
        "rfc_function": data.get("rfc_function", ""),
        "client_ip": data.get("client_ip", ""),
        "user_id": data.get("user_id", ""),
        "timestamp": data.get("timestamp", ""),
        "rule_triggered": rule,
        "rows_returned": int(data.get("rows_returned", 0)),
        "threshold": threshold,
        "severity": severity,
    }


def check_high_row_count(data: dict[str, Any], threshold: int) -> Optional[dict]:
    rows = int(data.get("rows_returned", 0))
    if rows > threshold:
        severity = "CRITICAL" if rows > threshold * 5 else "HIGH"
        return _build_alert(data, "HIGH_ROW_COUNT", threshold, severity)
    return None


def check_blocklisted_function(data: dict[str, Any], row_threshold: int) -> Optional[dict]:
    rfc_fn = data.get("rfc_function", "")
    rows = int(data.get("rows_returned", 0))
    if rfc_fn in BLOCKLISTED_FUNCTIONS and rows > row_threshold:
        return _build_alert(data, "BLOCKLISTED_FUNCTION", row_threshold, "HIGH")
    return None


def check_velocity(data: dict[str, Any], velocity_threshold: int) -> Optional[dict]:
    count = int(data.get("client_req_count_5m", 0))
    if count > velocity_threshold:
        return _build_alert(data, "VELOCITY_SPIKE", velocity_threshold, "MEDIUM")
    return None


def evaluate(
    data: dict[str, Any],
    high_row_threshold: int,
    blocklist_row_threshold: int,
    velocity_threshold: int,
) -> list[dict[str, Any]]:
    """
    Run all DLP rules against an analyzed_event.
    Returns a list of alert dicts (may be empty, one, or multiple alerts).
    """
    alerts = []

    alert = check_high_row_count(data, high_row_threshold)
    if alert:
        alerts.append(alert)

    alert = check_blocklisted_function(data, blocklist_row_threshold)
    if alert and not any(a["rule_triggered"] == "BLOCKLISTED_FUNCTION" for a in alerts):
        alerts.append(alert)

    alert = check_velocity(data, velocity_threshold)
    if alert:
        alerts.append(alert)

    return alerts

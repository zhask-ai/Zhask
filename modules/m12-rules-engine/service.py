"""IntegriShield M12 — Rules Engine Service.

Evaluates incoming API call events against a configurable set of security
rules and returns alert objects when a rule fires.

Rules cover 8 detection scenarios:
  1. bulk-extraction     — Large data exfiltration (>10MB outbound)
  2. off-hours-rfc       — API activity during non-business hours
  3. shadow-endpoint     — Calls to unregistered/unknown endpoints
  4. velocity-anomaly    — Too many calls in a short burst (>50 in 60s)
  5. privilege-escalation — Service account accessing admin-level functions
  6. geo-anomaly         — Source IP from unexpected geolocation
  7. data-staging        — Repeated small reads that total large volume
  8. credential-abuse    — Same credential used from multiple source IPs
"""

from __future__ import annotations

from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Thresholds (configurable via env in main.py)
# ---------------------------------------------------------------------------

BULK_EXTRACTION_BYTES = 10_000_000       # 10 MB
OFF_HOURS_START = 22                     # 10 PM
OFF_HOURS_END = 6                        # 6 AM
VELOCITY_THRESHOLD = 50                  # requests per window
VELOCITY_WINDOW_SECONDS = 60
DATA_STAGING_THRESHOLD = 5_000_000       # 5 MB cumulative
MULTI_IP_THRESHOLD = 3                   # unique IPs per credential

# In-memory counters for stateful rules (reset on restart — POC only)
_velocity_counters: dict[str, list[float]] = {}   # source_ip → [timestamps]
_staging_counters: dict[str, int] = {}             # source_ip → cumulative bytes
_credential_ips: dict[str, set[str]] = {}          # credential_id → {source_ips}

# Known admin-level RFC functions
_ADMIN_FUNCTIONS = frozenset({
    "RFC_READ_TABLE",
    "BAPI_USER_CHANGE",
    "BAPI_USER_CREATE",
    "SU01_MODIFY",
    "SM21_READ_LOG",
    "SE16_READ",
    "STRUST_MODIFY",
})

# Trusted IP prefixes — anything outside is a geo anomaly
_TRUSTED_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


def evaluate_event(event: dict) -> dict | None:
    """Evaluate a single event against all rules.

    Returns an alert dict if any rule fires, or None if the event is clean.
    The first matching rule wins (highest severity takes priority).
    """
    alerts = []

    # ── Rule 1: Bulk extraction ────────────────────────────────────
    bytes_out = int(event.get("bytes_out", 0))
    if bytes_out > BULK_EXTRACTION_BYTES:
        alerts.append(_make_alert(event, "bulk-extraction", "critical",
                                  detail=f"{bytes_out / 1_000_000:.1f}MB exfiltrated"))

    # ── Rule 2: Off-hours activity ─────────────────────────────────
    off_hours = _to_bool(event.get("off_hours", False))
    if off_hours:
        alerts.append(_make_alert(event, "off-hours-rfc", "medium",
                                  detail="API call during non-business hours"))

    # ── Rule 3: Shadow/unknown endpoint ────────────────────────────
    unknown_endpoint = _to_bool(event.get("unknown_endpoint", False))
    if unknown_endpoint:
        alerts.append(_make_alert(event, "shadow-endpoint", "critical",
                                  detail="Call to unregistered endpoint"))

    # ── Rule 4: Velocity anomaly ───────────────────────────────────
    source_ip = event.get("source_ip", "")
    if source_ip:
        import time
        now = time.time()
        timestamps = _velocity_counters.setdefault(source_ip, [])
        timestamps.append(now)
        # Prune old entries
        cutoff = now - VELOCITY_WINDOW_SECONDS
        _velocity_counters[source_ip] = [t for t in timestamps if t > cutoff]
        if len(_velocity_counters[source_ip]) > VELOCITY_THRESHOLD:
            alerts.append(_make_alert(event, "velocity-anomaly", "high",
                                      detail=f"{len(_velocity_counters[source_ip])} calls in {VELOCITY_WINDOW_SECONDS}s"))

    # ── Rule 5: Privilege escalation ───────────────────────────────
    rfc_function = event.get("rfc_function", event.get("function_name", ""))
    account_type = event.get("account_type", "")
    if rfc_function in _ADMIN_FUNCTIONS and account_type == "service":
        alerts.append(_make_alert(event, "privilege-escalation", "critical",
                                  detail=f"Service account invoking admin function {rfc_function}"))

    # ── Rule 6: Geo anomaly ────────────────────────────────────────
    if source_ip and not any(source_ip.startswith(prefix) for prefix in _TRUSTED_PREFIXES):
        alerts.append(_make_alert(event, "geo-anomaly", "high",
                                  detail=f"Call from non-internal IP {source_ip}"))

    # ── Rule 7: Data staging ───────────────────────────────────────
    if source_ip and 0 < bytes_out <= BULK_EXTRACTION_BYTES:
        cumulative = _staging_counters.get(source_ip, 0) + bytes_out
        _staging_counters[source_ip] = cumulative
        if cumulative > DATA_STAGING_THRESHOLD:
            alerts.append(_make_alert(event, "data-staging", "high",
                                      detail=f"Cumulative {cumulative / 1_000_000:.1f}MB from {source_ip}"))

    # ── Rule 8: Credential abuse ───────────────────────────────────
    credential_id = event.get("credential_id", event.get("user_id", ""))
    if credential_id and source_ip:
        ips = _credential_ips.setdefault(credential_id, set())
        ips.add(source_ip)
        if len(ips) >= MULTI_IP_THRESHOLD:
            alerts.append(_make_alert(event, "credential-abuse", "critical",
                                      detail=f"Credential {credential_id} used from {len(ips)} IPs"))

    # Return the highest-severity alert
    if not alerts:
        return None

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))
    return alerts[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(event: dict, scenario: str, severity: str, *, detail: str = "") -> dict:
    return {
        "event_id": event.get("event_id"),
        "scenario": scenario,
        "severity": severity,
        "detail": detail,
        "source_ip": event.get("source_ip", ""),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_module": "m12-rules-engine",
    }


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def alert_message(alert: dict) -> str:
    """Human-readable alert message."""
    scenario = alert.get("scenario", "unknown")
    detail = alert.get("detail", "")
    if detail:
        return f"{scenario}: {detail}"
    return f"{scenario} detected in SAP access pattern"

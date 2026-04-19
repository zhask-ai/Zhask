"""Rules evaluation service — all 8 detection rules for M12.

Rules:
  1. bulk-extraction      — Large data exfiltration (>10 MB outbound)
  2. off-hours-rfc        — API activity during non-business hours
  3. shadow-endpoint      — Calls to unregistered/unknown endpoints
  4. velocity-anomaly     — Too many calls in a short burst (>50 in 60s)
  5. privilege-escalation — Service account accessing admin-level functions
  6. geo-anomaly          — Source IP from unexpected geolocation
  7. data-staging         — Repeated small reads totalling large volume
  8. credential-abuse     — Same credential used from multiple source IPs
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from integrishield.m12.config import settings

# ---------------------------------------------------------------------------
# Known admin-level RFC functions
# ---------------------------------------------------------------------------

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
_TRUSTED_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.",
)

# In-memory counters for stateful rules (POC only; reset on restart)
_velocity_counters: dict[str, list[float]] = {}  # source_ip → [timestamps]
_staging_counters: dict[str, int] = {}            # source_ip → cumulative bytes
_credential_ips: dict[str, set[str]] = {}         # credential_id → {source_ips}

# Velocity window and threshold (can be overridden by importing code)
_VELOCITY_WINDOW_SECONDS = 60
_VELOCITY_THRESHOLD = 50
_DATA_STAGING_THRESHOLD = 5_000_000  # 5 MB cumulative
_MULTI_IP_THRESHOLD = 3              # unique IPs per credential


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_event(event: dict) -> dict | None:
    """Evaluate a single event against all 8 detection rules.

    Returns an alert dict for the highest-severity match, or ``None`` if
    the event is clean.
    """
    matched: list[dict] = []

    bytes_out = _int(event.get("bytes_out", 0))
    source_ip = str(event.get("source_ip", ""))
    rfc_function = str(event.get("rfc_function", event.get("function_name", "")))
    account_type = str(event.get("account_type", ""))
    credential_id = str(event.get("credential_id", event.get("user_id", "")))

    # ── Rule 1: Bulk extraction ────────────────────────────────────
    if bytes_out > settings.bulk_extraction_bytes:
        matched.append(_make_alert(event, "bulk-extraction", "critical",
                                   detail=f"{bytes_out / 1_000_000:.1f}MB exfiltrated"))

    # ── Rule 2: Off-hours activity ─────────────────────────────────
    if _to_bool(event.get("off_hours", False)):
        matched.append(_make_alert(event, "off-hours-rfc", "medium",
                                   detail="API call during non-business hours"))

    # ── Rule 3: Shadow/unknown endpoint ────────────────────────────
    if _to_bool(event.get("unknown_endpoint", False)):
        matched.append(_make_alert(event, "shadow-endpoint", "critical",
                                   detail="Call to unregistered endpoint"))

    # ── Rule 4: Velocity anomaly ───────────────────────────────────
    if source_ip:
        now = time.time()
        timestamps = _velocity_counters.setdefault(source_ip, [])
        timestamps.append(now)
        cutoff = now - _VELOCITY_WINDOW_SECONDS
        _velocity_counters[source_ip] = [t for t in timestamps if t > cutoff]
        count = len(_velocity_counters[source_ip])
        if count > _VELOCITY_THRESHOLD:
            matched.append(_make_alert(event, "velocity-anomaly", "high",
                                       detail=f"{count} calls in {_VELOCITY_WINDOW_SECONDS}s"))

    # ── Rule 5: Privilege escalation ───────────────────────────────
    if rfc_function in _ADMIN_FUNCTIONS and account_type == "service":
        matched.append(_make_alert(event, "privilege-escalation", "critical",
                                   detail=f"Service account invoking admin function {rfc_function}"))

    # ── Rule 6: Geo anomaly ────────────────────────────────────────
    if source_ip and not any(source_ip.startswith(p) for p in _TRUSTED_PREFIXES):
        matched.append(_make_alert(event, "geo-anomaly", "high",
                                   detail=f"Call from non-internal IP {source_ip}"))

    # ── Rule 7: Data staging ───────────────────────────────────────
    if source_ip and 0 < bytes_out <= settings.bulk_extraction_bytes:
        cumulative = _staging_counters.get(source_ip, 0) + bytes_out
        _staging_counters[source_ip] = cumulative
        if cumulative > _DATA_STAGING_THRESHOLD:
            matched.append(_make_alert(event, "data-staging", "high",
                                       detail=f"Cumulative {cumulative / 1_000_000:.1f}MB from {source_ip}"))

    # ── Rule 8: Credential abuse ───────────────────────────────────
    if credential_id and source_ip:
        ips = _credential_ips.setdefault(credential_id, set())
        ips.add(source_ip)
        if len(ips) >= _MULTI_IP_THRESHOLD:
            matched.append(_make_alert(event, "credential-abuse", "critical",
                                       detail=f"Credential {credential_id} used from {len(ips)} IPs"))

    if not matched:
        return None

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matched.sort(key=lambda a: _SEV_ORDER.get(a["severity"], 99))
    return matched[0]


def alert_message(alert: dict) -> str:
    """Human-readable message for an alert dict."""
    scenario = alert.get("scenario", "unknown")
    detail = alert.get("detail", "")
    if detail:
        return f"{scenario}: {detail}"
    return f"{scenario} detected in SAP access pattern"


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
        "message": f"{scenario}: {detail}" if detail else f"{scenario} detected in SAP access pattern",
    }


def _to_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

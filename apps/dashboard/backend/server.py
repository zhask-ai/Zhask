"""IntegriShield SOC Dashboard Backend — Full multi-stream consumer + REST API.

Subscribes to ALL 12 module Redis streams:
  M01 api_call_events       → rules engine → alert_events
  M03 analyzed_events       (consumed upstream by M08/M09)
  M04 zero_trust_events
  M05 mcp_query_events      (SAP MCP tool invocations)
  M06 credential_events
  M07 compliance_alerts     (compliance violations)
  M08 anomaly_scores
  M09 dlp_alerts            (data loss prevention)
  M10 incident_events       (incident lifecycle)
  M11 shadow_alerts         (unknown endpoint detections)
  M12 alert_events          (rules engine output)
  M13 sbom_scan_events      (SBOM / CVE scan results)
  M15 cloud_posture_events
"""

import hashlib
import hmac
import importlib.util
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("integrishield.dashboard")

# Ensure backend directory is importable (for action_handlers.py)
_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[3]
_M12_PKG_SRC = ROOT / "modules" / "m12-rules-engine" / "src"

REDIS_URL          = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_START_ID     = os.getenv("REDIS_START_ID", "0")
DATABASE_URL       = os.getenv("DATABASE_URL", "")
SERVER_PORT        = int(os.getenv("PORT", "8787"))
# Microservice URLs — empty = skip HTTP proxy; dashboard uses built-in demo data (POC).
M16_SERVICE_URL    = os.getenv("M16_SERVICE_URL", "").strip()
WEBHOOK_SECRET     = os.getenv("WEBHOOK_SECRET", "")
# Default True: demo POC — Redis/modules optional; synthetic data + stubs keep UI alive.
POC_DEMO_MODE      = os.getenv("INTEGRISHIELD_POC_MODE", "1").lower() in {"1", "true", "yes", "on"}
# Simple in-memory rate limiter for webhook intake: max N requests per window
_WEBHOOK_RL_MAX    = int(os.getenv("WEBHOOK_RL_MAX", "60"))
_WEBHOOK_RL_WINDOW = int(os.getenv("WEBHOOK_RL_WINDOW", "60"))
_webhook_rl_counts: dict[str, list[float]] = {}
_webhook_rl_lock   = threading.Lock()

# All module streams — matches each module's publish stream
STREAM_KEYS = {
    # M01 raw RFC calls → M12 evaluates these
    "api_calls":        os.getenv("STREAM_API_CALLS",        "integrishield:api_call_events"),
    # M04 zero-trust access decisions
    "zero_trust":       os.getenv("STREAM_ZERO_TRUST",       "integrishield:zero_trust_events"),
    # M05 SAP MCP tool invocations (publishes to mcp_query_events)
    "sap_mcp":          os.getenv("STREAM_SAP_MCP",          "integrishield:mcp_query_events"),
    # M06 credential lifecycle events
    "credentials":      os.getenv("STREAM_CREDENTIALS",      "integrishield:credential_events"),
    # M07 compliance violations & evidence
    "compliance":       os.getenv("STREAM_COMPLIANCE",       "integrishield:compliance_alerts"),
    # M08 ML anomaly scores
    "anomalies":        os.getenv("STREAM_ANOMALIES",        "integrishield:anomaly_scores"),
    # M09 DLP violations
    "dlp":              os.getenv("STREAM_DLP",              "integrishield:dlp_alerts"),
    # M10 incident lifecycle events
    "incidents":        os.getenv("STREAM_INCIDENTS",        "integrishield:incident_events"),
    # M11 shadow endpoint detections
    "shadow":           os.getenv("STREAM_SHADOW",           "integrishield:shadow_alerts"),
    # M12 rules engine output alerts
    "alerts":           os.getenv("STREAM_ALERTS",           "integrishield:alert_events"),
    # M13 SBOM scan results
    "sbom":             os.getenv("STREAM_SBOM",             "integrishield:sbom_scan_events"),
    # M15 multi-cloud posture findings
    "cloud_posture":    os.getenv("STREAM_CLOUD_POSTURE",    "integrishield:cloud_posture_events"),
    # M02 connector sentinel
    "connectors":       os.getenv("STREAM_CONNECTORS",       "integrishield:connector_events"),
    # M14 webhook gateway
    "webhooks":         os.getenv("STREAM_WEBHOOKS",         "integrishield:webhook_events"),
    # M03 integration traffic analyzer
    "traffic":          os.getenv("STREAM_TRAFFIC",          "integrishield:traffic_flow_events"),
}

# Whether the backend should also publish synthetic demo events to all streams
ENABLE_DEMO_GENERATOR = os.getenv("DEMO_GENERATOR", "1") not in ("0", "false", "no", "off")


# ──────────────────────────────────────────────────────────────
# Load M12 rules engine (full package) or demo stub — POC never hard-fails startup
# ──────────────────────────────────────────────────────────────

RULES_ENGINE_MODE = "unknown"


def _demo_stub_evaluate_event(event: dict) -> dict | None:
    """Lightweight rules used when M12 package is unavailable (demo / slim images)."""
    from datetime import datetime, timezone

    try:
        bo = int(event.get("bytes_out", 0))
    except (TypeError, ValueError):
        bo = 0
    oh = _to_bool(event.get("off_hours", False))
    unk = _to_bool(event.get("unknown_endpoint", False))
    if bo > 10_000_000:
        return {
            "event_id": event.get("event_id"),
            "scenario": "bulk-extraction",
            "severity": "critical",
            "detail": "Bulk transfer (demo stub)",
            "source_ip": event.get("source_ip", ""),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_module": "m12-rules-engine-demo",
        }
    if oh:
        return {
            "event_id": event.get("event_id"),
            "scenario": "off-hours-rfc",
            "severity": "medium",
            "detail": "Off-hours activity (demo stub)",
            "source_ip": event.get("source_ip", ""),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_module": "m12-rules-engine-demo",
        }
    if unk:
        return {
            "event_id": event.get("event_id"),
            "scenario": "shadow-endpoint",
            "severity": "critical",
            "detail": "Unknown endpoint (demo stub)",
            "source_ip": event.get("source_ip", ""),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_module": "m12-rules-engine-demo",
        }
    return None


def _demo_stub_alert_message(alert: dict) -> str:
    scenario = alert.get("scenario", "unknown")
    detail = alert.get("detail", "")
    return f"{scenario}: {detail}" if detail else f"{scenario} (demo stub)"


class _DemoRulesEngine:
    evaluate_event = staticmethod(_demo_stub_evaluate_event)
    alert_message = staticmethod(_demo_stub_alert_message)


def _load_rules_engine():
    """Import full M12 package when present; otherwise use embedded demo stub."""
    global RULES_ENGINE_MODE
    pkg_src = str(_M12_PKG_SRC)
    if pkg_src not in sys.path:
        sys.path.insert(0, pkg_src)
    try:
        import importlib as _il

        mod = _il.import_module("integrishield.m12.services")
        RULES_ENGINE_MODE = "m12-package"
        logger.info("Rules engine: full M12 package loaded")
        return mod
    except Exception as exc:
        RULES_ENGINE_MODE = "demo-stub"
        logger.warning(
            "Rules engine: using embedded demo stub (M12 package not importable: %s). "
            "This is normal for POC / demo deployments.",
            exc,
        )
        return _DemoRulesEngine()


rules_engine = _load_rules_engine()


# ──────────────────────────────────────────────────────────────
# Thread-safe data stores
# ──────────────────────────────────────────────────────────────

ALERTS      = deque(maxlen=500)
AUDIT       = deque(maxlen=500)
ANOMALIES   = deque(maxlen=200)
SAP_EVENTS  = deque(maxlen=200)
ZERO_TRUST  = deque(maxlen=200)
CREDENTIALS = deque(maxlen=200)
COMPLIANCE  = deque(maxlen=200)
DLP_ALERTS  = deque(maxlen=200)
INCIDENTS   = deque(maxlen=200)
SHADOW      = deque(maxlen=200)
SBOM_SCANS  = deque(maxlen=200)
CLOUD       = deque(maxlen=200)
CONNECTORS_Q= deque(maxlen=200)
WEBHOOKS    = deque(maxlen=200)
TRAFFIC     = deque(maxlen=200)
LOCK        = threading.Lock()

_DEMO_GEN = None  # set in main() once started

BACKEND_STATE = {
    "redis_connected": False,
    "last_stream_ids": {},
    "last_error": None,
    "streams_active": [],
    "events_processed": 0,
    # per-stream event counts
    "counts": {k: 0 for k in STREAM_KEYS},
}


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _decode(val):
    return val.decode("utf-8") if isinstance(val, bytes) else val


def _to_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_fields(fields: dict) -> dict:
    decoded = {_decode(k): _decode(v) for k, v in fields.items()}
    payload = {}
    if "data" in decoded:
        try:
            payload = json.loads(decoded["data"])
        except json.JSONDecodeError:
            pass
    event = {**decoded, **payload}
    for int_key in ("bytes_out", "row_count", "risk_score"):
        if int_key in event:
            try:
                event[int_key] = int(event[int_key])
            except (TypeError, ValueError):
                pass
    for bool_key in ("off_hours", "unknown_endpoint", "anomalous"):
        if bool_key in event:
            event[bool_key] = _to_bool(event[bool_key])
    return event


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ──────────────────────────────────────────────────────────────
# PostgreSQL persistence (optional)
# ──────────────────────────────────────────────────────────────

_pg_conn = None

def _get_pg():
    global _pg_conn
    if not DATABASE_URL:
        return None
    try:
        import psycopg2
        if _pg_conn is None or _pg_conn.closed:
            _pg_conn = psycopg2.connect(DATABASE_URL)
            _pg_conn.autocommit = True
        return _pg_conn
    except Exception:
        logger.warning("Postgres connection unavailable", exc_info=True)
        return None


def _persist_alert(alert: dict):
    conn = _get_pg()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_events
                   (event_id, actor, action, module_name, severity, scenario, source_ip, metadata)
                   VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT DO NOTHING""",
                (
                    "rules-engine", "alert_published",
                    alert.get("source_module", "m12-rules-engine"),
                    alert.get("severity", "medium"),
                    alert.get("scenario", "unknown"),
                    alert.get("source_ip"),
                    json.dumps(alert),
                ),
            )
    except Exception:
        logger.warning("Failed to persist alert to Postgres", exc_info=True)


# ──────────────────────────────────────────────────────────────
# Multi-stream consumer loop
# ──────────────────────────────────────────────────────────────

def stream_consumer_loop() -> None:
    try:
        import redis
    except ImportError as exc:
        with LOCK:
            BACKEND_STATE["last_error"] = f"missing_dependency: {exc}"
        return

    client = redis.from_url(REDIS_URL, decode_responses=False)
    last_ids = {name: REDIS_START_ID for name in STREAM_KEYS}

    while True:
        try:
            streams_arg = {key: last_ids[name] for name, key in STREAM_KEYS.items()}
            results = client.xread(streams_arg, count=50, block=3000)

            with LOCK:
                BACKEND_STATE["redis_connected"] = True
                BACKEND_STATE["last_error"] = None
                BACKEND_STATE["streams_active"] = list(STREAM_KEYS.keys())

            for stream_key_bytes, entries in (results or []):
                stream_key = _decode(stream_key_bytes)
                stream_name = next(
                    (n for n, k in STREAM_KEYS.items() if k == stream_key),
                    "unknown",
                )
                for stream_id, fields in entries:
                    sid     = _decode(stream_id) if isinstance(stream_id, bytes) else stream_id
                    started = time.time()
                    event   = _parse_fields(fields)
                    event["_stream"]    = stream_name
                    event["_stream_id"] = sid

                    with LOCK:
                        BACKEND_STATE["events_processed"] += 1
                        BACKEND_STATE["last_stream_ids"][stream_name] = sid
                        BACKEND_STATE["counts"][stream_name] = BACKEND_STATE["counts"].get(stream_name, 0) + 1

                    _route_event(stream_name, event, started)
                    last_ids[stream_name] = sid

        except Exception as exc:
            with LOCK:
                BACKEND_STATE["redis_connected"] = False
                BACKEND_STATE["last_error"] = str(exc)
            time.sleep(1.5)


# ──────────────────────────────────────────────────────────────
# Event router
# ──────────────────────────────────────────────────────────────

def _route_event(stream_name: str, event: dict, started: float):
    handlers = {
        "api_calls":   lambda e: _handle_api_call(e, started),
        "zero_trust":  _handle_zero_trust,
        "sap_mcp":     _handle_sap,
        "credentials": _handle_credential,
        "compliance":  _handle_compliance,
        "anomalies":   _handle_anomaly,
        "dlp":         _handle_dlp,
        "incidents":   _handle_incident,
        "shadow":      _handle_shadow,
        "alerts":      _handle_external_alert,
        "sbom":        _handle_sbom,
        "cloud_posture": _handle_cloud,
        "connectors":  _handle_connector,
        "webhooks":    _handle_webhook,
        "traffic":     _handle_traffic,
    }
    fn = handlers.get(stream_name)
    if fn:
        fn(event)


# ──────────────────────────────────────────────────────────────
# Stream handlers
# ──────────────────────────────────────────────────────────────

def _handle_api_call(event: dict, started: float):
    """M01 → M12 rules engine → alert."""
    alert = rules_engine.evaluate_event(event)
    if alert is None:
        return
    latency_ms = int((time.time() - started) * 1000)
    alert["latencyMs"] = latency_ms
    alert["message"]   = rules_engine.alert_message(alert)
    alert["ts"]        = _now_iso()
    alert["severity"]  = str(alert.get("severity", "medium")).lower()
    with LOCK:
        ALERTS.appendleft(alert)
        AUDIT.appendleft({"ts": alert["ts"], "actor": "rules-engine",
                          "action": "alert_published", "module": "m12-rules-engine", "status": "ok"})
    _persist_alert(alert)


def _handle_anomaly(event: dict):
    """M08 anomaly score."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        ANOMALIES.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m08-anomaly-detection",
                          "action": "anomaly_scored", "module": "m08-anomaly-detection", "status": "ok"})


def _handle_sap(event: dict):
    """M05 SAP MCP tool invocation."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        SAP_EVENTS.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m05-sap-mcp-suite",
                          "action": event.get("tool_name", "tool_invoked"),
                          "module": "m05-sap-mcp-suite", "status": "ok"})


def _handle_zero_trust(event: dict):
    """M04 zero-trust decision."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        ZERO_TRUST.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m04-zero-trust-fabric",
                          "action": event.get("decision", "evaluated"),
                          "module": "m04-zero-trust-fabric", "status": "ok"})


def _handle_credential(event: dict):
    """M06 credential vault event."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        CREDENTIALS.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m06-credential-vault",
                          "action": event.get("action", "credential_event"),
                          "module": "m06-credential-vault", "status": "ok"})


def _handle_compliance(event: dict):
    """M07 compliance alert / evidence."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        COMPLIANCE.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m07-compliance-autopilot",
                          "action": event.get("control_id", "compliance_check"),
                          "module": "m07-compliance-autopilot", "status": "ok"})


def _handle_dlp(event: dict):
    """M09 DLP violation."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        DLP_ALERTS.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m09-dlp",
                          "action": event.get("rule", "dlp_violation"),
                          "module": "m09-dlp", "status": "ok"})


def _handle_incident(event: dict):
    """M10 incident lifecycle event."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        INCIDENTS.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m10-incident-response",
                          "action": event.get("action", "incident_updated"),
                          "module": "m10-incident-response", "status": "ok"})


def _handle_shadow(event: dict):
    """M11 shadow endpoint detection."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        SHADOW.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m11-shadow-integration",
                          "action": "shadow_endpoint_detected",
                          "module": "m11-shadow-integration", "status": "ok"})


def _handle_sbom(event: dict):
    """M13 SBOM scan result."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        SBOM_SCANS.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m13-sbom-scanner",
                          "action": event.get("scan_status", "scan_completed"),
                          "module": "m13-sbom-scanner", "status": "ok"})


def _handle_cloud(event: dict):
    """M15 cloud posture finding."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        CLOUD.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m15-multicloud-ispm",
                          "action": "finding_ingested",
                          "module": "m15-multicloud-ispm", "status": "ok"})


def _handle_external_alert(event: dict):
    """Pre-evaluated alert from M12 or any module."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        ALERTS.appendleft(event)


def _handle_connector(event: dict):
    """M02 connector sentinel event."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        CONNECTORS_Q.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m02-connector-sentinel",
                          "action": event.get("status", "connector_check"),
                          "module": "m02-connector-sentinel", "status": "ok"})


def _handle_webhook(event: dict):
    """M14 webhook gateway event."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        WEBHOOKS.appendleft(event)
        AUDIT.appendleft({"ts": event["ts"], "actor": "m14-webhook-gateway",
                          "action": event.get("result", "webhook_received"),
                          "module": "m14-webhook-gateway", "status": "ok"})


def _handle_traffic(event: dict):
    """M03 traffic analyzer — data-in-transit classification."""
    event.setdefault("ts", event.get("timestamp_utc", _now_iso()))
    with LOCK:
        TRAFFIC.appendleft(event)


# ──────────────────────────────────────────────────────────────
# Claude AI Chat Handler — M05 SAP Security Assistant
# ──────────────────────────────────────────────────────────────

# 17 SAP MCP tool definitions mirrored here for Claude's tool_use API
_SAP_TOOLS_FOR_CLAUDE = [
    {"name": "query_events",        "description": "Query recent SAP RFC/API call events intercepted by IntegriShield. Returns call records with user, IP, function module, bytes transferred.", "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}, "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "get_anomaly_scores",   "description": "Get ML anomaly scores from the IsolationForest engine. Returns events with anomaly probability.", "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}, "since_minutes": {"type": "integer", "default": 60}}}},
    {"name": "list_alerts",          "description": "List recent security alerts. Includes bulk extraction, off-hours RFC, shadow endpoint, velocity anomaly alerts.", "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 20}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", ""], "default": ""}}}},
    {"name": "list_users",           "description": "List SAP user accounts with status, type, and last login.", "input_schema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}, "user_type": {"type": "string", "default": "all"}}}},
    {"name": "get_user_roles",       "description": "Get role and profile assignments for a SAP user.", "input_schema": {"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "string"}}}},
    {"name": "get_auth_objects",     "description": "Query SAP authorization objects (S_RFC, S_TCODE, S_DEVELOP) for a user or role.", "input_schema": {"type": "object", "properties": {"user_id": {"type": "string", "default": ""}, "auth_object": {"type": "string", "default": ""}}}},
    {"name": "get_sod_violations",   "description": "Detect Segregation of Duties (SoD) violations in SAP authorizations. Maps to SOX controls.", "input_schema": {"type": "object", "properties": {"user_id": {"type": "string", "default": ""}, "severity_filter": {"type": "string", "default": "all"}}}},
    {"name": "get_dormant_users",    "description": "Identify dormant SAP user accounts inactive for N days.", "input_schema": {"type": "object", "properties": {"inactive_days": {"type": "integer", "default": 90}}}},
    {"name": "get_locked_users",     "description": "List currently locked SAP user accounts with lock reason and timestamp.", "input_schema": {"type": "object", "properties": {"lock_type": {"type": "string", "default": "all"}}}},
    {"name": "get_failed_logins",    "description": "Get failed SAP login attempts from security audit log (SM20).", "input_schema": {"type": "object", "properties": {"since_minutes": {"type": "integer", "default": 60}, "user_id": {"type": "string", "default": ""}}}},
    {"name": "check_critical_auth",  "description": "Check for critical SAP authorizations: SAP_ALL, debug access, user admin, unrestricted RFC.", "input_schema": {"type": "object", "properties": {"auth_type": {"type": "string", "default": "all"}}}},
    {"name": "monitor_rfc_calls",    "description": "Monitor live RFC call volume by function module, user, or IP. Flags velocity anomalies.", "input_schema": {"type": "object", "properties": {"since_minutes": {"type": "integer", "default": 30}, "group_by": {"type": "string", "default": "function_module"}}}},
    {"name": "read_table",           "description": "Read SAP table rows with built-in DLP protection. Blocks sensitive tables (PA0008, BSEG, USR02).", "input_schema": {"type": "object", "required": ["table_name"], "properties": {"table_name": {"type": "string"}, "max_rows": {"type": "integer", "default": 100}}}},
    {"name": "get_change_logs",      "description": "Get SAP change document logs for user master and authorization changes.", "input_schema": {"type": "object", "properties": {"object_class": {"type": "string", "default": "ALL"}, "since_minutes": {"type": "integer", "default": 1440}}}},
    {"name": "analyze_report_access","description": "Analyze which users can run sensitive SAP reports (payroll, financial, user admin).", "input_schema": {"type": "object", "properties": {"report_category": {"type": "string", "default": "all"}}}},
    {"name": "get_security_policy",  "description": "Get SAP system security policy: password rules, logon lockout, RFC security, session timeout.", "input_schema": {"type": "object", "properties": {"category": {"type": "string", "default": "all"}}}},
    {"name": "run_security_check",   "description": "Evaluate a SAP RFC call event against detection rules for bulk extraction, off-hours, and shadow endpoints.", "input_schema": {"type": "object", "required": ["event"], "properties": {"event": {"type": "object"}}}},
]

def _execute_sap_tool(tool_name: str, tool_input: dict) -> dict:
    """Execute an SAP tool call using live event data from in-memory stores."""
    with LOCK:
        alerts_snap    = list(ALERTS)[:50]
        anomalies_snap = list(ANOMALIES)[:30]
        sap_snap       = list(SAP_EVENTS)[:30]
        shadow_snap    = list(SHADOW)[:20]

    if tool_name == "query_events":
        limit = min(int(tool_input.get("limit", 20)), 100)
        return {"events": alerts_snap[:limit], "total": len(alerts_snap[:limit])}

    elif tool_name == "get_anomaly_scores":
        limit = min(int(tool_input.get("limit", 20)), 100)
        return {"anomaly_events": anomalies_snap[:limit], "total": len(anomalies_snap[:limit])}

    elif tool_name == "list_alerts":
        limit = min(int(tool_input.get("limit", 20)), 100)
        sev   = tool_input.get("severity", "")
        items = [a for a in alerts_snap if not sev or a.get("severity") == sev]
        return {"alerts": items[:limit], "total": len(items)}

    elif tool_name == "list_users":
        seen: dict[str, dict] = {}
        for ev in alerts_snap:
            uid = ev.get("user_id", "")
            if uid and uid not in seen:
                seen[uid] = {"user_id": uid, "user_type": "service" if uid.startswith("SVC") else "dialog", "last_seen": ev.get("ts")}
        return {"users": list(seen.values())[:50], "total": len(seen)}

    elif tool_name == "get_dormant_users":
        return {"dormant_users": [
            {"user_id": "OLD_ADMIN", "days_inactive": 213, "user_type": "dialog"},
            {"user_id": "SVC_LEGACY", "days_inactive": 167, "user_type": "service"},
        ], "total": 2}

    elif tool_name == "get_locked_users":
        locked_users = {ev.get("user_id") for ev in alerts_snap if ev.get("severity") == "critical"}
        return {"locked_users": [{"user_id": u, "lock_type": "failed_logon"} for u in list(locked_users)[:5]], "total": len(locked_users)}

    elif tool_name == "get_failed_logins":
        limit = min(int(tool_input.get("limit", 50)), 200)
        attempts = [{"user_id": a.get("user_id"), "source_ip": a.get("source_ip"), "timestamp": a.get("ts"), "reason": "WRONG_PASSWORD"} for a in alerts_snap if a.get("severity") in ("critical", "high")]
        return {"failed_attempts": attempts[:limit], "total": len(attempts)}

    elif tool_name == "get_sod_violations":
        users_risky = list({a.get("user_id") for a in alerts_snap if a.get("severity") == "critical"})[:5]
        violations = [{"user_id": u, "rule": "AP_GL_POSTING", "severity": "critical", "sox_control": "AC-6"} for u in users_risky]
        return {"violations": violations, "total": len(violations)}

    elif tool_name == "check_critical_auth":
        return {"critical_assignments": [
            {"auth": "SAP_ALL", "users": ["ROOT"], "risk": "CRITICAL", "sox_control": "AC-6"},
            {"auth": "S_DEVELOP(ACTVT=02)", "users": ["SYSADMIN"], "risk": "HIGH", "sox_control": "CM-2"},
        ], "immediate_action_required": True}

    elif tool_name == "monitor_rfc_calls":
        from collections import Counter
        counts = Counter(a.get("scenario", "unknown") for a in alerts_snap)
        return {"calls": [{"key": k, "call_count": v} for k, v in counts.most_common(10)], "total_calls": len(alerts_snap)}

    elif tool_name == "get_security_policy":
        return {"policy": {"password": {"login/min_password_lng": {"value": "8", "recommended": "12", "compliant": False}}, "logon": {"login/fails_to_user_lock": {"value": "5", "recommended": "3", "compliant": False}}}, "non_compliant_parameters": 4, "risk_level": "HIGH"}

    elif tool_name == "analyze_report_access":
        return {"reports": [{"report": "RSUSR002", "description": "User authorization analysis", "users": ["SEC_ADMIN", "ROOT"], "sox": "AC-2"}, {"report": "RPCLSTB2", "description": "Payroll cluster", "users": ["BATCHJOB"], "sox": "AC-6"}], "total": 2}

    elif tool_name == "get_change_logs":
        changes = [{"changed_by": a.get("user_id"), "object_class": "AUTH", "change_type": "MODIFY", "timestamp": a.get("ts")} for a in alerts_snap[:10] if a.get("severity") == "critical"]
        return {"changes": changes, "total": len(changes)}

    elif tool_name == "read_table":
        table = tool_input.get("table_name", "").upper()
        sensitive = {"PA0008", "USR02", "BSEG", "REGUH", "PA0001"}
        if table in sensitive:
            return {"table": table, "blocked": True, "reason": f"DLP: {table} is classified sensitive — access blocked"}
        return {"table": table, "blocked": False, "rows": [{"KEY": f"ROW{i}"} for i in range(5)], "row_count": 5}

    elif tool_name == "get_user_roles":
        uid = tool_input.get("user_id", "")
        _roles = {"ROOT": ["SAP_ALL", "SAP_BC_BASIS_ADMIN"], "SYSADMIN": ["SAP_BC_BASIS_ADMIN"], "SEC_ADMIN": ["SAP_BC_USER_ADMIN"]}
        return {"user_id": uid, "roles": _roles.get(uid, ["Z_STANDARD_USER"]), "has_critical": uid in ("ROOT", "SYSADMIN")}

    elif tool_name == "get_auth_objects":
        return {"auth_objects": {"S_RFC": {"ACTVT": ["16"], "RFC_NAME": ["*"]}, "S_TCODE": {"TCD": ["SE16", "SU01"]}}}

    elif tool_name == "run_security_check":
        event = tool_input.get("event", {})
        result_alerts = []
        if int(event.get("bytes_transferred", 0)) > 10_000_000:
            result_alerts.append({"scenario": "bulk-extraction", "severity": "critical"})
        if event.get("off_hours"):
            result_alerts.append({"scenario": "off-hours-rfc", "severity": "medium"})
        if event.get("unknown_endpoint"):
            result_alerts.append({"scenario": "shadow-endpoint", "severity": "critical"})
        return {"matched": bool(result_alerts), "alert": result_alerts[0] if result_alerts else None}

    elif tool_name == "shadow_detections":
        return {"detections": [{"endpoint": s.get("endpoint"), "user_id": s.get("user_id"), "severity": "critical"} for s in shadow_snap], "total": len(shadow_snap)}

    return {"error": f"Tool '{tool_name}' executed but returned no data"}


# ──────────────────────────────────────────────────────────────
# M16 Policy Decisions — demo data
# ──────────────────────────────────────────────────────────────

import random, uuid as _uuid

_M16_DEMO_USERS = [
    ("alice.soc@corp.com", "SOC_ADMIN"),
    ("bob.analyst@corp.com", "SOC_ANALYST"),
    ("carol.audit@corp.com", "AUDITOR"),
    ("dave.analyst@corp.com", "SOC_ANALYST"),
    ("svc-sbom@corp.com", "SERVICE"),
]
_M16_DEMO_TOOLS = [
    ("rfc_read_table", {"table": "BKPF", "max_rows": 5000}),
    ("get_user_roles", {"user_id": "BAUER_M"}),
    ("rfc_call_function", {"func": "BAPI_USER_CREATE"}),
    ("list_incidents", {"severity": "critical"}),
    ("get_authorization_profile", {"profile": "SAP_ALL"}),
    ("rfc_read_table", {"table": "KNA1", "max_rows": 200}),
    ("unknown_tool_xyz", {}),
    ("get_compliance_status", {"framework": "SOX"}),
]
_M16_DECISIONS_STORE: list[dict] = []
_M16_DECISIONS_LOCK = threading.Lock()
_M16_COUNTERS: dict[str, int] = {"total": 0, "ALLOW": 0, "DENY": 0, "MODIFY": 0}

_M16_RULES = [
    {"rule_id": "R-001", "description": "SOC admins can invoke any MCP tool without restriction.", "roles": ["SOC_ADMIN"], "tool_pattern": "*", "action": "ALLOW", "modifier": {}},
    {"rule_id": "R-010", "description": "Auditors may read metadata and compliance tools only.", "roles": ["AUDITOR"], "tool_pattern": "get_*", "action": "ALLOW", "modifier": {}},
    {"rule_id": "R-011", "description": "Auditors invoking table reads are row-capped to 500.", "roles": ["AUDITOR"], "tool_pattern": "rfc_read_table", "action": "MODIFY", "modifier": {"max_rows": 500}},
    {"rule_id": "R-012", "description": "Auditors cannot call any write or execute tool.", "roles": ["AUDITOR"], "tool_pattern": "rfc_call_function", "action": "DENY", "modifier": {}},
    {"rule_id": "R-020", "description": "Analysts reading SAP tables are row-capped to 1000.", "roles": ["SOC_ANALYST"], "tool_pattern": "rfc_read_table", "action": "MODIFY", "modifier": {"max_rows": 1000}},
    {"rule_id": "R-021", "description": "Analysts may query user, role, and authorization metadata.", "roles": ["SOC_ANALYST"], "tool_pattern": "get_*", "action": "ALLOW", "modifier": {}},
    {"rule_id": "R-022", "description": "Analysts may run incident and compliance lookups.", "roles": ["SOC_ANALYST"], "tool_pattern": "list_*", "action": "ALLOW", "modifier": {}},
    {"rule_id": "R-023", "description": "Analysts cannot invoke privileged RFC functions directly.", "roles": ["SOC_ANALYST"], "tool_pattern": "rfc_call_function", "action": "DENY", "modifier": {}},
    {"rule_id": "R-030", "description": "Service accounts may publish webhook and evidence events.", "roles": ["SERVICE"], "tool_pattern": "publish_*", "action": "ALLOW", "modifier": {}},
    {"rule_id": "R-031", "description": "Service accounts may not read SAP tables.", "roles": ["SERVICE"], "tool_pattern": "rfc_*", "action": "DENY", "modifier": {}},
]

def _m16_seed_demo() -> None:
    import time as _time
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    demo_decisions = [
        {"user": "alice.soc@corp.com", "role": "SOC_ADMIN", "tool": "rfc_call_function", "decision": "ALLOW", "rule": "R-001", "reason": "SOC admins can invoke any MCP tool without restriction."},
        {"user": "bob.analyst@corp.com", "role": "SOC_ANALYST", "tool": "rfc_read_table", "decision": "MODIFY", "rule": "R-020", "reason": "Analysts reading SAP tables are row-capped to 1000."},
        {"user": "carol.audit@corp.com", "role": "AUDITOR", "tool": "rfc_call_function", "decision": "DENY", "rule": "R-012", "reason": "Auditors cannot call any write or execute tool."},
        {"user": "dave.analyst@corp.com", "role": "SOC_ANALYST", "tool": "get_user_roles", "decision": "ALLOW", "rule": "R-021", "reason": "Analysts may query user, role, and authorization metadata."},
        {"user": "bob.analyst@corp.com", "role": "SOC_ANALYST", "tool": "unknown_tool_xyz", "decision": "DENY", "rule": "R-DEFAULT", "reason": "No policy rule permits role='SOC_ANALYST' to invoke tool='unknown_tool_xyz'. Default-deny applied."},
        {"user": "svc-sbom@corp.com", "role": "SERVICE", "tool": "rfc_read_table", "decision": "DENY", "rule": "R-031", "reason": "Service accounts may not read SAP tables."},
        {"user": "alice.soc@corp.com", "role": "SOC_ADMIN", "tool": "get_authorization_profile", "decision": "ALLOW", "rule": "R-001", "reason": "SOC admins can invoke any MCP tool without restriction."},
        {"user": "carol.audit@corp.com", "role": "AUDITOR", "tool": "rfc_read_table", "decision": "MODIFY", "rule": "R-011", "reason": "Auditors invoking table reads are row-capped to 500."},
        {"user": "dave.analyst@corp.com", "role": "SOC_ANALYST", "tool": "list_incidents", "decision": "ALLOW", "rule": "R-022", "reason": "Analysts may run incident and compliance lookups."},
        {"user": "bob.analyst@corp.com", "role": "SOC_ANALYST", "tool": "get_compliance_status", "decision": "ALLOW", "rule": "R-021", "reason": "Analysts may query user, role, and authorization metadata."},
    ]
    for i, d in enumerate(demo_decisions):
        ts = (now - timedelta(minutes=len(demo_decisions) - i)).replace(microsecond=0)
        entry = {
            "audit_id": str(_uuid.uuid4()),
            "timestamp": ts.isoformat(),
            "decision": d["decision"],
            "rule_id": d["rule"],
            "reason": d["reason"],
            "user_id": d["user"],
            "role": d["role"],
            "tool_name": d["tool"],
            "source_module": "m05",
            "session_id": f"sess-{_uuid.uuid4().hex[:8]}",
        }
        _M16_DECISIONS_STORE.append(entry)
        _M16_COUNTERS["total"] += 1
        _M16_COUNTERS[d["decision"]] = _M16_COUNTERS.get(d["decision"], 0) + 1

_m16_seed_demo()

def _m16_decisions_snapshot(limit: int = 100) -> dict:
    with _M16_DECISIONS_LOCK:
        items = list(reversed(_M16_DECISIONS_STORE))[:limit]
    return {"decisions": items, "counters": dict(_M16_COUNTERS)}

def _m16_simulate_evaluate(body: dict) -> dict:
    user_id = body.get("user_id", "unknown@corp.com")
    role = body.get("role", "SOC_ANALYST")
    tool_name = body.get("tool_name", "rfc_read_table")
    decisions_map = {
        ("SOC_ADMIN", "*"): ("ALLOW", "R-001"),
        ("SOC_ANALYST", "rfc_read_table"): ("MODIFY", "R-020"),
        ("SOC_ANALYST", "get_"): ("ALLOW", "R-021"),
        ("SOC_ANALYST", "list_"): ("ALLOW", "R-022"),
        ("SOC_ANALYST", "rfc_call_function"): ("DENY", "R-023"),
        ("AUDITOR", "rfc_read_table"): ("MODIFY", "R-011"),
        ("AUDITOR", "rfc_call_function"): ("DENY", "R-012"),
        ("AUDITOR", "get_"): ("ALLOW", "R-010"),
        ("SERVICE", "rfc_"): ("DENY", "R-031"),
    }
    decision, rule_id = "DENY", "R-DEFAULT"
    reason = f"No policy rule permits role='{role}' to invoke tool='{tool_name}'. Default-deny applied."
    for (r, t), (dec, rid) in decisions_map.items():
        if r == role or r == "*":
            if t == "*" or tool_name == t or tool_name.startswith(t):
                decision, rule_id = dec, rid
                for rule in _M16_RULES:
                    if rule["rule_id"] == rid:
                        reason = rule["description"]
                break
    audit_id = str(_uuid.uuid4())
    entry = {
        "audit_id": audit_id, "timestamp": _now_iso(), "decision": decision,
        "rule_id": rule_id, "reason": reason, "user_id": user_id, "role": role,
        "tool_name": tool_name, "source_module": body.get("source_module", "m05"),
        "session_id": body.get("session_id", f"sess-{_uuid.uuid4().hex[:8]}"),
    }
    with _M16_DECISIONS_LOCK:
        _M16_DECISIONS_STORE.append(entry)
        _M16_COUNTERS["total"] += 1
        _M16_COUNTERS[decision] = _M16_COUNTERS.get(decision, 0) + 1
    return entry


# ──────────────────────────────────────────────────────────────
# M13 CVE Feed Status — demo data
# ──────────────────────────────────────────────────────────────

_M13_LAST_REFRESH = {"nvd": "2026-04-18T06:12:00Z", "osv": "2026-04-18T06:14:33Z"}
_M13_CVE_COUNT = {"nvd": 2847, "osv": 1203}
_M13_TOP_CVES = [
    {"cve_id": "CVE-2025-23121", "cvss": 9.8, "severity": "CRITICAL", "dependency": "requests==2.28.0", "description": "HTTP header injection via redirect chain in requests library.", "published": "2025-11-14"},
    {"cve_id": "CVE-2025-31200", "cvss": 8.8, "severity": "HIGH", "dependency": "pydantic==1.10.9", "description": "Remote code execution via crafted validation model in pydantic v1.", "published": "2025-10-02"},
    {"cve_id": "CVE-2024-56334", "cvss": 8.1, "severity": "HIGH", "dependency": "cryptography==41.0.2", "description": "Weak RSA key generation under specific entropy conditions.", "published": "2024-12-19"},
    {"cve_id": "CVE-2025-29441", "cvss": 7.5, "severity": "HIGH", "dependency": "aiohttp==3.9.1", "description": "Path traversal in aiohttp static file handler.", "published": "2025-09-07"},
    {"cve_id": "CVE-2024-52302", "cvss": 6.5, "severity": "MEDIUM", "dependency": "uvicorn==0.23.2", "description": "HTTP/1.1 request smuggling in uvicorn connection handler.", "published": "2024-11-28"},
]

def _m13_cve_feed_snapshot() -> dict:
    return {
        "feeds": {
            "nvd": {"last_refresh": _M13_LAST_REFRESH["nvd"], "cached_cves": _M13_CVE_COUNT["nvd"], "status": "healthy"},
            "osv": {"last_refresh": _M13_LAST_REFRESH["osv"], "cached_cves": _M13_CVE_COUNT["osv"], "status": "healthy"},
        },
        "top_cves": _M13_TOP_CVES,
        "total_cached": _M13_CVE_COUNT["nvd"] + _M13_CVE_COUNT["osv"],
        "cache_age_minutes": 372,
    }

def _m13_refresh_feeds() -> dict:
    _M13_LAST_REFRESH["nvd"] = _now_iso()
    _M13_LAST_REFRESH["osv"] = _now_iso()
    _M13_CVE_COUNT["nvd"] += random.randint(0, 12)
    _M13_CVE_COUNT["osv"] += random.randint(0, 5)
    return {"status": "refreshed", "nvd": _M13_LAST_REFRESH["nvd"], "osv": _M13_LAST_REFRESH["osv"], "new_cves_added": random.randint(2, 15)}


# ──────────────────────────────────────────────────────────────
# M14 Webhook DLQ — demo data
# ──────────────────────────────────────────────────────────────

_M14_DLQ_ENTRIES = [
    {"delivery_id": "dlv-001", "subscriber": "siem.corp.com/hook", "event_type": "anomaly_event", "attempts": 5, "last_error": "Connection timeout after 10s", "last_attempt": "2026-04-18T09:43:12Z", "next_retry": None, "status": "dead"},
    {"delivery_id": "dlv-002", "subscriber": "pagerduty.com/v2/enqueue", "event_type": "incident_event", "attempts": 3, "last_error": "HTTP 429 Too Many Requests", "last_attempt": "2026-04-18T10:01:55Z", "next_retry": "2026-04-18T10:16:55Z", "status": "retrying"},
    {"delivery_id": "dlv-003", "subscriber": "slack.com/api/chat.postMessage", "event_type": "dlp_alert", "attempts": 2, "last_error": "HTTP 403 Forbidden — token revoked", "last_attempt": "2026-04-18T10:05:30Z", "next_retry": "2026-04-18T10:15:30Z", "status": "retrying"},
    {"delivery_id": "dlv-004", "subscriber": "splunk.corp.com/collector", "event_type": "compliance_evidence", "attempts": 5, "last_error": "SSL certificate verification failed", "last_attempt": "2026-04-18T07:20:00Z", "next_retry": None, "status": "dead"},
    {"delivery_id": "dlv-005", "subscriber": "teams.microsoft.com/webhook/xxx", "event_type": "alert_event", "attempts": 1, "last_error": "DNS resolution failed: teams.microsoft.com", "last_attempt": "2026-04-18T10:10:05Z", "next_retry": "2026-04-18T10:20:05Z", "status": "retrying"},
]
_M14_DLQ_STORE = list(_M14_DLQ_ENTRIES)
_M14_DLQ_LOCK = threading.Lock()

def _m14_dlq_snapshot(limit: int = 50) -> dict:
    with _M14_DLQ_LOCK:
        items = list(_M14_DLQ_STORE)[:limit]
    dead = sum(1 for i in items if i["status"] == "dead")
    retrying = sum(1 for i in items if i["status"] == "retrying")
    return {"entries": items, "total": len(items), "dead": dead, "retrying": retrying}

def _m14_retry_dlq(delivery_id: str) -> dict:
    with _M14_DLQ_LOCK:
        for entry in _M14_DLQ_STORE:
            if entry["delivery_id"] == delivery_id:
                entry["status"] = "retrying"
                entry["attempts"] += 1
                entry["last_attempt"] = _now_iso()
                entry["last_error"] = "Manually triggered retry"
                return {"ok": True, "delivery_id": delivery_id, "message": "Retry queued"}
    return {"ok": False, "error": "delivery_id not found"}


def _handle_chat(body: dict) -> dict:
    """Handle Claude SAP security chat request using tool use."""
    message = str(body.get("message", "")).strip()
    history = body.get("history", [])  # list of {role, content} dicts

    if not message:
        return {"error": "message is required"}

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        # Graceful degradation — return a helpful canned response
        return {
            "response": (
                "The Claude AI assistant requires an ANTHROPIC_API_KEY environment variable. "
                "Set it in your shell: `export ANTHROPIC_API_KEY=sk-ant-...` then restart the backend. "
                "All 17 SAP security tools are registered and ready."
            ),
            "tool_calls": [],
            "degraded": True,
        }

    try:
        import anthropic as _ant  # type: ignore[import]
    except ImportError:
        return {"error": "anthropic package not installed. Run: pip install anthropic>=0.40.0", "degraded": True}

    client = _ant.Anthropic(api_key=api_key)
    system_prompt = (
        "You are the IntegriShield SAP Security Assistant — an AI analyst embedded in a real-time "
        "security operations center monitoring SAP systems. You have access to 17 security tools that "
        "query live event streams from IntegriShield's middleware security platform.\n\n"
        "When answering questions about users, threats, compliance, or SAP security posture, "
        "ALWAYS call the relevant tools first to get real-time data. "
        "Be concise, actionable, and security-focused. "
        "Highlight critical findings in your response. "
        "Reference specific users, IPs, and RFC function modules from the data you retrieve."
    )

    messages = []
    for h in history[-6:]:  # last 6 turns for context
        role = h.get("role", "user")
        content = h.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": message})

    tool_calls_made: list[dict] = []
    max_rounds = 5

    for _ in range(max_rounds):
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system_prompt,
            tools=_SAP_TOOLS_FOR_CLAUDE,
            messages=messages,
        )

        if resp.stop_reason == "end_turn":
            text = "".join(b.text for b in resp.content if hasattr(b, "text"))
            return {"response": text, "tool_calls": tool_calls_made}

        if resp.stop_reason == "tool_use":
            # Collect all tool use blocks
            tool_results = []
            assistant_content = [b.__dict__ if hasattr(b, "__dict__") else b for b in resp.content]
            messages.append({"role": "assistant", "content": resp.content})

            for block in resp.content:
                if block.type == "tool_use":
                    result = _execute_sap_tool(block.name, block.input)
                    tool_calls_made.append({"tool": block.name, "input": block.input, "result": result})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str),
                    })

            messages.append({"role": "user", "content": tool_results})
            continue

        # Unexpected stop reason
        break

    # Fallback: extract any text from last response
    text = "".join(b.text for b in resp.content if hasattr(b, "text")) or "I was unable to complete that analysis."
    return {"response": text, "tool_calls": tool_calls_made}


# ──────────────────────────────────────────────────────────────
# Service proxy helpers (forward to real microservices)
# ──────────────────────────────────────────────────────────────

def _proxy_get(url: str) -> dict | None:
    """GET the URL and return the parsed JSON, or None if unavailable."""
    if not url or not str(url).startswith("http"):
        return None
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=2) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _proxy_post(url: str, body: dict) -> dict | None:
    """POST JSON body to the URL and return the parsed JSON, or None if unavailable."""
    if not url or not str(url).startswith("http"):
        return None
    try:
        import urllib.request
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────
# Webhook rate-limiter + HMAC verification
# ──────────────────────────────────────────────────────────────

def _webhook_rate_limit(source: str) -> bool:
    """Return True if the request is within the rate limit, False if exceeded."""
    now = time.time()
    cutoff = now - _WEBHOOK_RL_WINDOW
    with _webhook_rl_lock:
        timestamps = _webhook_rl_counts.setdefault(source, [])
        # Prune old entries
        _webhook_rl_counts[source] = [t for t in timestamps if t > cutoff]
        if len(_webhook_rl_counts[source]) >= _WEBHOOK_RL_MAX:
            return False
        _webhook_rl_counts[source].append(now)
    return True


def _webhook_verify_signature(body_bytes: bytes, sig_header: str) -> bool:
    """Verify HMAC-SHA256 signature against WEBHOOK_SECRET.

    Accepts signatures in the formats:
      - ``sha256=<hex>``       (GitHub-style)
      - raw hex string
    If WEBHOOK_SECRET is not configured, any non-empty signature header passes.
    """
    if not WEBHOOK_SECRET:
        return bool(sig_header)  # secret not configured — presence check only

    secret_bytes = WEBHOOK_SECRET.encode("utf-8")
    expected_mac = hmac.HMAC(secret_bytes, body_bytes, digestmod=hashlib.sha256).hexdigest()

    provided = sig_header.removeprefix("sha256=").strip()
    return hmac.compare_digest(expected_mac, provided)


# ──────────────────────────────────────────────────────────────
# HTTP API Handler
# ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self) -> None:
        try:
            self._do_POST_inner()
        except Exception as exc:
            import traceback; traceback.print_exc()
            try: self._json(500, {"error": str(exc)})
            except Exception: pass

    def _do_POST_inner(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}") if length else {}
        name   = body.get("name", "")

        if parsed.path == "/api/modules/start":
            if not name:
                self._json(400, {"error": "name required"}); return
            self._json(200, start_module(name))

        elif parsed.path == "/api/modules/stop":
            if not name:
                self._json(400, {"error": "name required"}); return
            self._json(200, stop_module(name))

        elif parsed.path == "/api/modules/start-all":
            results = []
            for cfg in LAUNCH_CONFIGS:
                results.append(start_module(cfg["name"]))
            self._json(200, {"results": results})

        elif parsed.path == "/api/modules/stop-all":
            results = []
            for cfg in LAUNCH_CONFIGS:
                s = _proc_status(cfg["name"])
                if s["status"] == "running":
                    results.append(stop_module(cfg["name"]))
            self._json(200, {"results": results})

        elif parsed.path == "/api/chat":
            self._json(200, _handle_chat(body))

        elif parsed.path == "/api/demo/replay":
            scenario = (body.get("scenario") or "all").lower()
            if _DEMO_GEN is None:
                self._json(503, {"error": "demo generator not running"}); return
            count = _DEMO_GEN.replay_scenario(scenario)
            self._json(200, {"replayed": scenario, "events_published": count})

        elif parsed.path == "/api/actions":
            import action_handlers as ah
            drawer_type = body.get("drawer_type", "alert")
            action_id   = body.get("action_id", "fix")
            ev          = body.get("event", {})
            operator    = body.get("operator", "anonymous")
            result      = ah.dispatch(drawer_type, action_id, ev, operator)
            self._json(200, result)

        elif parsed.path == "/api/actions/undo":
            import action_handlers as ah
            token  = body.get("undo_token", "")
            result = ah.undo_action(token)
            self._json(200, result)

        elif parsed.path == "/api/m13/cve-feed/refresh":
            self._json(200, _m13_refresh_feeds()); return

        elif parsed.path == "/api/m14/dlq/retry":
            delivery_id = body.get("delivery_id", "")
            self._json(200, _m14_retry_dlq(delivery_id)); return

        elif parsed.path == "/api/m16/evaluate":
            proxied = _proxy_post(f"{M16_SERVICE_URL}/policy/evaluate", body)
            self._json(200, proxied if proxied is not None else _m16_simulate_evaluate(body)); return

        elif parsed.path.startswith("/webhook/"):
            # M14 webhook intake — HMAC-SHA256 verification + rate limiting
            source = parsed.path.rsplit("/", 1)[-1] or "custom"

            # Rate limit check
            if not _webhook_rate_limit(source):
                logger.warning("Webhook rate limit exceeded for source=%s", source)
                self._json(429, {"error": "rate_limit_exceeded", "source": source}); return

            # Signature verification (POC without WEBHOOK_SECRET accepts any POST for demos)
            sig = self.headers.get("X-Signature") or self.headers.get("X-Hub-Signature-256") or ""
            body_bytes_for_hmac = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
            if POC_DEMO_MODE and not WEBHOOK_SECRET:
                sig_valid = True
            else:
                sig_valid = _webhook_verify_signature(body_bytes_for_hmac, sig)
            result = "accepted" if sig_valid else "rejected"
            if not sig_valid:
                reason = "missing signature" if not sig else "invalid signature"
                logger.warning("Webhook %s from source=%s: %s", result, source, reason)
            event = {
                "source":          source,
                "result":          result,
                "signature_valid": sig_valid,
                "reason":          "signature verified" if sig_valid else ("missing signature" if not sig else "invalid signature"),
                "event_type":      body.get("event_type", "push"),
                "severity":        "high" if result == "rejected" else "low",
            }
            if _DEMO_GEN is not None:
                _DEMO_GEN.publish("webhooks", event)
            self._json(200 if sig_valid else 401, {"result": result, "source": source})

        else:
            self._json(404, {"error": "not found"})

    def do_GET(self) -> None:
        try:
            self._do_GET_inner()
        except Exception as exc:
            import traceback; traceback.print_exc()
            try: self._json(500, {"error": str(exc)})
            except Exception: pass

    def _do_GET_inner(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        try:
            limit = max(1, min(int(params.get("limit", ["40"])[0]), 500))
        except (TypeError, ValueError):
            self._json(400, {"error": "invalid_limit"}); return

        with LOCK:
            state = dict(BACKEND_STATE)

        path = parsed.path

        # ── Module Processes ────────────────────────────────────
        if path == "/api/modules/processes":
            self._json(200, {"processes": all_module_statuses(), "modules": all_module_statuses()}); return

        # ── Health ──────────────────────────────────────────────
        if path == "/api/health":
            self._json(200, {
                "status":              "ok" if state["redis_connected"] or POC_DEMO_MODE else "degraded",
                "demo_poc":            POC_DEMO_MODE,
                "rules_engine":        RULES_ENGINE_MODE,
                "demo_generator":      ENABLE_DEMO_GENERATOR,
                "m16_proxy_configured": bool(M16_SERVICE_URL),
                "redis_url":           REDIS_URL,
                "redis_connected":     state["redis_connected"],
                "streams_active":      state["streams_active"],
                "events_processed":    state["events_processed"],
                "last_stream_ids":     state["last_stream_ids"],
                "last_error":          state["last_error"],
                "postgres_configured": bool(DATABASE_URL),
                "stream_counts":       state["counts"],
            }); return

        # ── Module health (all 13 modules) ──────────────────────
        if path == "/api/modules/health":
            with LOCK:
                counts = dict(BACKEND_STATE["counts"])
            self._json(200, {
                "modules": {
                    "m01-api-gateway-shield":   {"stream": STREAM_KEYS["api_calls"],   "status": "consuming", "events": counts.get("api_calls", 0)},
                    "m03-traffic-analyzer":     {"stream": "integrishield:analyzed_events", "status": "upstream", "events": 0},
                    "m04-zero-trust-fabric":    {"stream": STREAM_KEYS["zero_trust"],  "status": "consuming", "events": counts.get("zero_trust", 0)},
                    "m05-sap-mcp-suite":        {"stream": STREAM_KEYS["sap_mcp"],     "status": "consuming", "events": counts.get("sap_mcp", 0)},
                    "m06-credential-vault":     {"stream": STREAM_KEYS["credentials"], "status": "consuming", "events": counts.get("credentials", 0)},
                    "m07-compliance-autopilot": {"stream": STREAM_KEYS["compliance"],  "status": "consuming", "events": counts.get("compliance", 0)},
                    "m08-anomaly-detection":    {"stream": STREAM_KEYS["anomalies"],   "status": "consuming", "events": counts.get("anomalies", 0)},
                    "m09-dlp":                  {"stream": STREAM_KEYS["dlp"],         "status": "consuming", "events": counts.get("dlp", 0)},
                    "m10-incident-response":    {"stream": STREAM_KEYS["incidents"],   "status": "consuming", "events": counts.get("incidents", 0)},
                    "m11-shadow-integration":   {"stream": STREAM_KEYS["shadow"],      "status": "consuming", "events": counts.get("shadow", 0)},
                    "m12-rules-engine":         {"stream": STREAM_KEYS["alerts"],      "status": "consuming", "events": counts.get("alerts", 0)},
                    "m13-sbom-scanner":         {"stream": STREAM_KEYS["sbom"],        "status": "consuming", "events": counts.get("sbom", 0)},
                    "m15-multicloud-ispm":      {"stream": STREAM_KEYS["cloud_posture"], "status": "consuming", "events": counts.get("cloud_posture", 0)},
                },
                "events_processed": state["events_processed"],
            }); return

        # ── Snapshot all stores ─────────────────────────────────
        with LOCK:
            alerts      = list(ALERTS)[:limit]
            audit       = list(AUDIT)[:limit]
            anomalies   = list(ANOMALIES)[:limit]
            sap         = list(SAP_EVENTS)[:limit]
            zt          = list(ZERO_TRUST)[:limit]
            creds       = list(CREDENTIALS)[:limit]
            compliance  = list(COMPLIANCE)[:limit]
            dlp         = list(DLP_ALERTS)[:limit]
            incidents   = list(INCIDENTS)[:limit]
            shadow      = list(SHADOW)[:limit]
            sbom        = list(SBOM_SCANS)[:limit]
            cloud       = list(CLOUD)[:limit]
            connectors  = list(CONNECTORS_Q)[:limit]
            webhooks    = list(WEBHOOKS)[:limit]
            traffic     = list(TRAFFIC)[:limit]

        routes = {
            "/api/alerts":       lambda: {"alerts":      alerts},
            "/api/audit":        lambda: {"rows":        audit},
            "/api/anomalies":    lambda: {"anomalies":   anomalies},
            "/api/sap-activity": lambda: {"events":      sap},
            "/api/zero-trust":   lambda: {"evaluations": zt},
            "/api/credentials":  lambda: {"events":      creds},
            "/api/compliance":   lambda: {"findings":    compliance},
            "/api/dlp":          lambda: {"violations":  dlp},
            "/api/incidents":    lambda: {"incidents":   incidents},
            "/api/shadow":       lambda: {"detections":  shadow},
            "/api/sbom":         lambda: {"scans":       sbom},
            "/api/cloud-posture":lambda: {"findings":    cloud},
            "/api/connectors":   lambda: {"connectors":  connectors},
            "/api/webhooks":     lambda: {"webhooks":    webhooks},
            "/api/traffic":      lambda: {"flows":       traffic},
        }
        if path in routes:
            self._json(200, routes[path]()); return

        # ── Compliance report (per framework) ──────────────────
        if path == "/api/compliance/report":
            fw = (params.get("framework", ["SOC2"])[0] or "SOC2").upper()
            with LOCK:
                findings = [f for f in COMPLIANCE if str(f.get("framework","")).upper() == fw]
                total_alerts  = len(ALERTS)
                total_incid   = len(INCIDENTS)
            passed = sum(1 for f in findings if f.get("status") == "pass")
            failed = sum(1 for f in findings if f.get("status") == "fail")
            controls = sorted({f.get("control_id","") for f in findings if f.get("control_id")})
            self._json(200, {
                "framework":       fw,
                "generated_at":    _now_iso(),
                "controls_evaluated": len(controls),
                "controls":        controls,
                "total_findings":  len(findings),
                "passed":          passed,
                "failed":          failed,
                "posture_score":   round(100 * passed / max(len(findings), 1), 1) if findings else 100.0,
                "evidence_events": total_alerts + total_incid,
                "recent_evidence": findings[:20],
            }); return

        # ── Aggregate stats ─────────────────────────────────────
        if path == "/api/stats":
            with LOCK:
                all_alerts  = list(ALERTS)
                n_anomalies = len(ANOMALIES)
                n_sap       = len(SAP_EVENTS)
                n_zt        = len(ZERO_TRUST)
                n_cred      = len(CREDENTIALS)
                n_comp      = len(COMPLIANCE)
                n_dlp       = len(DLP_ALERTS)
                n_inc       = len(INCIDENTS)
                n_shadow    = len(SHADOW)
                n_sbom      = len(SBOM_SCANS)
                n_cloud     = len(CLOUD)
                n_conn      = len(CONNECTORS_Q)
                n_webhook   = len(WEBHOOKS)
                n_traffic   = len(TRAFFIC)
                counts      = dict(BACKEND_STATE["counts"])
            critical  = sum(1 for a in all_alerts if a.get("severity") == "critical")
            latencies = [int(a["latencyMs"]) for a in all_alerts if "latencyMs" in a]
            avg_lat   = round(sum(latencies) / len(latencies), 1) if latencies else 0
            self._json(200, {
                "total_alerts":       len(all_alerts),
                "critical_alerts":    critical,
                "avg_latency_ms":     avg_lat,
                "anomalies_count":    n_anomalies,
                "sap_events_count":   n_sap,
                "zero_trust_evals":   n_zt,
                "credential_events":  n_cred,
                "compliance_findings":n_comp,
                "dlp_violations":     n_dlp,
                "incident_count":     n_inc,
                "shadow_detections":  n_shadow,
                "sbom_scans":         n_sbom,
                "cloud_findings":     n_cloud,
                "connector_events":   n_conn,
                "webhook_events":     n_webhook,
                "traffic_flows":      n_traffic,
                "stream_counts":      counts,
            }); return

        # ── M16 Policy Decisions (proxy → real service, fallback to demo) ──
        if path == "/api/m16/decisions":
            proxied = _proxy_get(f"{M16_SERVICE_URL}/policy/decisions?limit={limit}")
            self._json(200, proxied if proxied is not None else _m16_decisions_snapshot(limit)); return
        if path == "/api/m16/rules":
            proxied = _proxy_get(f"{M16_SERVICE_URL}/policy/rules")
            self._json(200, proxied if proxied is not None else {"rules": _M16_RULES, "default_action": "DENY"}); return

        # ── M13 CVE Feed Status (demo data) ─────────────────────
        if path == "/api/m13/cve-feed":
            self._json(200, _m13_cve_feed_snapshot()); return

        # ── M14 Webhook DLQ (demo data) ─────────────────────────
        if path == "/api/m14/dlq":
            self._json(200, _m14_dlq_snapshot(limit)); return

        if path == "/api/actions":
            import action_handlers as ah
            f_type   = params.get("type",   [None])[0]
            f_actor  = params.get("actor",  [None])[0]
            f_action = params.get("action", [None])[0]
            rows = ah._read_action_log(limit=limit, filter_type=f_type,
                                       filter_actor=f_actor, filter_action=f_action)
            self._json(200, {"actions": rows, "total": len(rows)}); return

        if path == "/api/actions/state":
            import action_handlers as ah
            self._json(200, ah.get_state_flags()); return

        self._json(404, {"error": "not_found"})

    def log_message(self, *_):
        pass


# ──────────────────────────────────────────────────────────────
# Process Manager — start/stop modules via launch.json configs
# ──────────────────────────────────────────────────────────────

_LAUNCH_JSON = ROOT / ".claude" / "launch.json"
_PROC_LOCK   = threading.Lock()
_PROCESSES: dict[str, dict] = {}   # name → {proc, config, started_at, log}

def _load_launch_configs() -> list[dict]:
    try:
        with open(_LAUNCH_JSON) as f:
            data = json.load(f)
        # Exclude docker/compose entries and Dashboard Backend itself
        skip = {"POC Full Stack (Docker Compose)", "POC Dev4 Stack (Dashboard + Redis)", "Dashboard Backend"}
        return [c for c in data.get("configurations", []) if c["name"] not in skip]
    except FileNotFoundError:
        logger.info("launch.json not found at %s — module launcher disabled", _LAUNCH_JSON)
        return []
    except Exception:
        logger.warning("Failed to load launch.json", exc_info=True)
        return []

LAUNCH_CONFIGS: list[dict] = _load_launch_configs()
LAUNCH_MAP: dict[str, dict] = {c["name"]: c for c in LAUNCH_CONFIGS}

def _proc_status(name: str) -> dict:
    import time as _time
    with _PROC_LOCK:
        entry = _PROCESSES.get(name)
    if not entry:
        return {"name": name, "label": name, "status": "stopped", "pid": None,
                "port": LAUNCH_MAP.get(name, {}).get("port"), "started_at": None,
                "log_lines": [], "uptime_s": None}
    proc = entry["proc"]
    rc   = proc.poll()
    status = "stopped" if rc is not None else "running"
    started = entry["started_at"]
    uptime = None
    if status == "running" and started:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            uptime = round((datetime.now(timezone.utc) - dt).total_seconds())
        except Exception:
            logger.debug("Could not calculate uptime for %s", name, exc_info=True)
    return {
        "name":       name,
        "label":      name,
        "status":     status,
        "pid":        proc.pid if rc is None else None,
        "port":       entry["config"].get("port"),
        "started_at": started,
        "exit_code":  rc,
        "log_lines":  entry.get("log", [])[-50:],
        "uptime_s":   uptime,
    }

def start_module(name: str) -> dict:
    cfg = LAUNCH_MAP.get(name)
    if not cfg:
        return {"error": f"unknown module: {name}"}
    with _PROC_LOCK:
        # Kill stale process if present
        entry = _PROCESSES.get(name)
        if entry and entry["proc"].poll() is None:
            return {"error": f"{name} already running", "pid": entry["proc"].pid}

    env = {**os.environ, **(cfg.get("env") or {})}
    # Resolve PYTHONPATH relative to repo root
    if "PYTHONPATH" in env:
        parts = [str(ROOT / p) for p in env["PYTHONPATH"].split(":")]
        env["PYTHONPATH"] = ":".join(parts)

    cmd = [cfg["runtimeExecutable"]] + cfg.get("runtimeArgs", [])
    try:
        log_lines: list[str] = []
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Background thread to capture output
        def _read_logs():
            for line in proc.stdout:
                log_lines.append(line.rstrip())
                if len(log_lines) > 200:
                    log_lines.pop(0)
        threading.Thread(target=_read_logs, daemon=True).start()

        with _PROC_LOCK:
            _PROCESSES[name] = {"proc": proc, "config": cfg, "started_at": _now_iso(), "log": log_lines}
        return {"started": name, "pid": proc.pid, "cmd": cmd}
    except Exception as e:
        return {"error": str(e)}

def stop_module(name: str) -> dict:
    with _PROC_LOCK:
        entry = _PROCESSES.pop(name, None)
    if not entry:
        return {"error": f"{name} not running"}
    proc = entry["proc"]
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    return {"stopped": name, "exit_code": proc.returncode}

def all_module_statuses() -> list[dict]:
    return [_proc_status(c["name"]) for c in LAUNCH_CONFIGS]


# ──────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────

def main() -> None:
    global _DEMO_GEN
    t = threading.Thread(target=stream_consumer_loop, daemon=True)
    t.start()

    if ENABLE_DEMO_GENERATOR:
        try:
            from demo_generator import start_demo_generator
            _DEMO_GEN = start_demo_generator(REDIS_URL, STREAM_KEYS)
            print(f"  Demo gen   : publishing synthetic events to {len(STREAM_KEYS)} streams")
        except Exception as exc:
            print(f"  Demo gen   : DISABLED ({exc})")

    server = ThreadingHTTPServer(("0.0.0.0", SERVER_PORT), Handler)
    print("=" * 64)
    print("  IntegriShield SOC Dashboard Backend")
    print("=" * 64)
    print(f"  Listening  : http://0.0.0.0:{SERVER_PORT}")
    print(f"  Redis      : {REDIS_URL}")
    print(f"  Postgres   : {'configured' if DATABASE_URL else 'disabled'}")
    print(f"  Streams    : {len(STREAM_KEYS)}")
    for name, key in STREAM_KEYS.items():
        print(f"    {name:<18} → {key}")
    print("=" * 64)
    server.serve_forever()


if __name__ == "__main__":
    main()

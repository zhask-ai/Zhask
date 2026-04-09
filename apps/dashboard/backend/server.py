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

import importlib.util
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[3]
RULES_ENGINE_PATH = ROOT / "modules" / "m12-rules-engine" / "service.py"

REDIS_URL       = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_START_ID  = os.getenv("REDIS_START_ID", "$")
DATABASE_URL    = os.getenv("DATABASE_URL", "")
SERVER_PORT     = int(os.getenv("PORT", "8787"))

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
}


# ──────────────────────────────────────────────────────────────
# Load M12 rules engine
# ──────────────────────────────────────────────────────────────

def _load_rules_engine():
    spec = importlib.util.spec_from_file_location("m12_service", RULES_ENGINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load rules engine from {RULES_ENGINE_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

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
LOCK        = threading.Lock()

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
        pass


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
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        try:
            limit = max(1, min(int(params.get("limit", ["40"])[0]), 500))
        except (TypeError, ValueError):
            self._json(400, {"error": "invalid_limit"}); return

        with LOCK:
            state = dict(BACKEND_STATE)

        path = parsed.path

        # ── Health ──────────────────────────────────────────────
        if path == "/api/health":
            self._json(200, {
                "status":              "ok" if state["redis_connected"] else "degraded",
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
        }
        if path in routes:
            self._json(200, routes[path]()); return

        # ── Aggregate stats ─────────────────────────────────────
        if path == "/api/stats":
            with LOCK:
                all_alerts = list(ALERTS)
            critical   = sum(1 for a in all_alerts if a.get("severity") == "critical")
            latencies  = [a["latencyMs"] for a in all_alerts if "latencyMs" in a]
            avg_lat    = round(sum(latencies) / len(latencies), 1) if latencies else 0
            with LOCK:
                counts = dict(BACKEND_STATE["counts"])
            self._json(200, {
                "total_alerts":       len(list(ALERTS)),
                "critical_alerts":    critical,
                "avg_latency_ms":     avg_lat,
                "anomalies_count":    len(list(ANOMALIES)),
                "sap_events_count":   len(list(SAP_EVENTS)),
                "zero_trust_evals":   len(list(ZERO_TRUST)),
                "credential_events":  len(list(CREDENTIALS)),
                "compliance_findings":len(list(COMPLIANCE)),
                "dlp_violations":     len(list(DLP_ALERTS)),
                "incident_count":     len(list(INCIDENTS)),
                "shadow_detections":  len(list(SHADOW)),
                "sbom_scans":         len(list(SBOM_SCANS)),
                "cloud_findings":     len(list(CLOUD)),
                "stream_counts":      counts,
            }); return

        self._json(404, {"error": "not_found"})

    def log_message(self, *_):
        pass


# ──────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────

def main() -> None:
    t = threading.Thread(target=stream_consumer_loop, daemon=True)
    t.start()

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

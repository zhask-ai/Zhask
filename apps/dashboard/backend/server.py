"""IntegriShield SOC Dashboard Backend — Multi-stream consumer + REST API.

Dev4 dashboard backend that:
- Consumes events from ALL module Redis streams (M01, M05, M08, M12, M04, M06, M15)
- Runs the M12 rules engine on raw API call events
- Persists alerts and audit entries to PostgreSQL
- Serves REST API endpoints for the dashboard frontend
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[3]
RULES_ENGINE_PATH = ROOT / "modules" / "m12-rules-engine" / "service.py"

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_START_ID = os.getenv("REDIS_START_ID", "$")
DATABASE_URL = os.getenv("DATABASE_URL", "")  # empty = skip Postgres

# All module streams the dashboard should subscribe to
STREAM_KEYS = {
    "api_calls": os.getenv("STREAM_API_CALLS", "integrishield:api_call_events"),
    "anomalies": os.getenv("STREAM_ANOMALIES", "integrishield:anomaly_scores"),
    "sap_mcp": os.getenv("STREAM_SAP_MCP", "integrishield:sap_mcp_events"),
    "alerts": os.getenv("STREAM_ALERTS", "integrishield:alert_events"),
    "zero_trust": os.getenv("STREAM_ZERO_TRUST", "integrishield:zero_trust_events"),
    "credentials": os.getenv("STREAM_CREDENTIALS", "integrishield:credential_events"),
    "cloud_posture": os.getenv("STREAM_CLOUD_POSTURE", "integrishield:cloud_posture_events"),
}


# ---------------------------------------------------------------------------
# Load rules engine (legacy import from service.py)
# ---------------------------------------------------------------------------

def load_rules_engine():
    spec = importlib.util.spec_from_file_location("m12_rules_engine_service", RULES_ENGINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load rules engine module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rules_engine = load_rules_engine()


# ---------------------------------------------------------------------------
# Thread-safe data stores
# ---------------------------------------------------------------------------

ALERTS = deque(maxlen=500)
AUDIT = deque(maxlen=500)
ANOMALIES = deque(maxlen=200)
SAP_EVENTS = deque(maxlen=200)
ZERO_TRUST = deque(maxlen=200)
CREDENTIALS = deque(maxlen=200)
CLOUD_POSTURE = deque(maxlen=200)
LOCK = threading.Lock()

BACKEND_STATE = {
    "redis_connected": False,
    "last_stream_ids": {},
    "last_error": None,
    "streams_active": [],
    "events_processed": 0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode(val):
    return val.decode("utf-8") if isinstance(val, bytes) else val


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_stream_fields(fields) -> dict:
    decoded = {_decode(k): _decode(v) for k, v in fields.items()}
    payload = {}
    if "data" in decoded:
        try:
            payload = json.loads(decoded["data"])
        except json.JSONDecodeError:
            payload = {}
    event = {**decoded, **payload}

    if "bytes_out" in event:
        event["bytes_out"] = int(event["bytes_out"])
    if "off_hours" in event:
        event["off_hours"] = _to_bool(event["off_hours"])
    if "unknown_endpoint" in event:
        event["unknown_endpoint"] = _to_bool(event["unknown_endpoint"])
    return event


# ---------------------------------------------------------------------------
# PostgreSQL persistence (optional — skipped if DATABASE_URL is empty)
# ---------------------------------------------------------------------------

_pg_conn = None


def _get_pg_connection():
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
    conn = _get_pg_connection()
    if conn is None:
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_events
                   (event_id, actor, action, module_name, severity, scenario, source_ip, metadata)
                   VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT DO NOTHING""",
                (
                    "rules-engine",
                    "alert_published",
                    alert.get("source_module", "m12-rules-engine"),
                    alert.get("severity", "medium"),
                    alert.get("scenario", "unknown"),
                    alert.get("source_ip"),
                    json.dumps(alert),
                ),
            )
    except Exception:
        pass  # Non-blocking — DB write failures don't crash the consumer


# ---------------------------------------------------------------------------
# Multi-stream consumer loop
# ---------------------------------------------------------------------------

def stream_consumer_loop() -> None:
    try:
        import redis
    except ImportError as exc:
        with LOCK:
            BACKEND_STATE["last_error"] = f"missing_dependency: {exc}"
        return

    client = redis.from_url(REDIS_URL, decode_responses=False)

    # Track last-seen ID per stream
    last_ids = {name: REDIS_START_ID for name in STREAM_KEYS}

    while True:
        try:
            # Build the streams dict for XREAD
            streams_arg = {key: last_ids[name] for name, key in STREAM_KEYS.items()}
            results = client.xread(streams_arg, count=50, block=3000)

            with LOCK:
                BACKEND_STATE["redis_connected"] = True
                BACKEND_STATE["last_error"] = None
                BACKEND_STATE["streams_active"] = list(STREAM_KEYS.keys())

            for stream_key_bytes, entries in results:
                stream_key = _decode(stream_key_bytes)

                # Find which logical name maps to this stream key
                stream_name = "unknown"
                for name, key in STREAM_KEYS.items():
                    if key == stream_key:
                        stream_name = name
                        break

                for stream_id, fields in entries:
                    sid = _decode(stream_id) if isinstance(stream_id, bytes) else stream_id
                    started = time.time()
                    src = parse_stream_fields(fields)
                    src["_stream"] = stream_name
                    src["_stream_id"] = sid

                    with LOCK:
                        BACKEND_STATE["events_processed"] += 1
                        BACKEND_STATE["last_stream_ids"][stream_name] = sid

                    # Route based on source stream
                    if stream_name == "api_calls":
                        _handle_api_call_event(src, started)
                    elif stream_name == "anomalies":
                        _handle_anomaly(src)
                    elif stream_name == "sap_mcp":
                        _handle_sap_event(src)
                    elif stream_name == "zero_trust":
                        _handle_zero_trust(src)
                    elif stream_name == "credentials":
                        _handle_credential(src)
                    elif stream_name == "cloud_posture":
                        _handle_cloud_posture(src)
                    elif stream_name == "alerts":
                        _handle_external_alert(src)

                    last_ids[stream_name] = sid

        except Exception as exc:
            with LOCK:
                BACKEND_STATE["redis_connected"] = False
                BACKEND_STATE["last_error"] = str(exc)
            time.sleep(1.5)


# ---------------------------------------------------------------------------
# Stream handlers — one per module type
# ---------------------------------------------------------------------------

def _handle_api_call_event(src: dict, started: float):
    """Process M01 API call events through the rules engine."""
    alert = rules_engine.evaluate_event(src)
    if alert is None:
        return

    latency_ms = int((time.time() - started) * 1000)
    alert["latencyMs"] = latency_ms
    alert["message"] = rules_engine.alert_message(alert)
    alert["ts"] = datetime.now(timezone.utc).isoformat()
    alert["severity"] = str(alert["severity"]).lower()

    with LOCK:
        ALERTS.appendleft(alert)
        AUDIT.appendleft({
            "ts": alert["ts"],
            "actor": "rules-engine",
            "action": "alert_published",
            "module": "m12-rules-engine",
            "status": "ok",
        })

    _persist_alert(alert)


def _handle_anomaly(src: dict):
    """Process M08 anomaly scores."""
    src["ts"] = src.get("timestamp_utc", datetime.now(timezone.utc).isoformat())
    with LOCK:
        ANOMALIES.appendleft(src)
        AUDIT.appendleft({
            "ts": src["ts"],
            "actor": "anomaly-detection",
            "action": "anomaly_scored",
            "module": "m08-anomaly-detection",
            "status": "ok",
        })


def _handle_sap_event(src: dict):
    """Process M05 SAP MCP events."""
    src["ts"] = src.get("timestamp_utc", datetime.now(timezone.utc).isoformat())
    with LOCK:
        SAP_EVENTS.appendleft(src)
        AUDIT.appendleft({
            "ts": src["ts"],
            "actor": "sap-mcp-suite",
            "action": "tool_invoked",
            "module": "m05-sap-mcp-suite",
            "status": "ok",
        })


def _handle_zero_trust(src: dict):
    """Process M04 zero-trust decisions."""
    src["ts"] = src.get("timestamp_utc", datetime.now(timezone.utc).isoformat())
    with LOCK:
        ZERO_TRUST.appendleft(src)
        AUDIT.appendleft({
            "ts": src["ts"],
            "actor": "zero-trust-fabric",
            "action": src.get("decision", "evaluated"),
            "module": "m04-zero-trust-fabric",
            "status": "ok",
        })


def _handle_credential(src: dict):
    """Process M06 credential events."""
    src["ts"] = src.get("timestamp_utc", datetime.now(timezone.utc).isoformat())
    with LOCK:
        CREDENTIALS.appendleft(src)
        AUDIT.appendleft({
            "ts": src["ts"],
            "actor": "credential-vault",
            "action": src.get("action", "credential_event"),
            "module": "m06-credential-vault",
            "status": "ok",
        })


def _handle_cloud_posture(src: dict):
    """Process M15 cloud posture events."""
    src["ts"] = src.get("timestamp_utc", datetime.now(timezone.utc).isoformat())
    with LOCK:
        CLOUD_POSTURE.appendleft(src)
        AUDIT.appendleft({
            "ts": src["ts"],
            "actor": "multicloud-ispm",
            "action": "finding_ingested",
            "module": "m15-multicloud-ispm",
            "status": "ok",
        })


def _handle_external_alert(src: dict):
    """Process pre-evaluated alerts from M12 (or other modules)."""
    src["ts"] = src.get("timestamp_utc", datetime.now(timezone.utc).isoformat())
    with LOCK:
        ALERTS.appendleft(src)


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        try:
            limit = int(params.get("limit", ["40"])[0])
        except (TypeError, ValueError):
            self._send_json(400, {"error": "invalid_limit"})
            return
        limit = max(1, min(limit, 500))

        with LOCK:
            state = dict(BACKEND_STATE)

        # ---- Health ----
        if parsed.path == "/api/health":
            self._send_json(200, {
                "status": "ok" if state["redis_connected"] else "degraded",
                "redis_url": REDIS_URL,
                "streams": state["streams_active"],
                "redis_connected": state["redis_connected"],
                "events_processed": state["events_processed"],
                "last_stream_ids": state["last_stream_ids"],
                "last_error": state["last_error"],
                "postgres_configured": bool(DATABASE_URL),
            })
            return

        # ---- Module health aggregation ----
        if parsed.path == "/api/modules/health":
            self._send_json(200, {
                "modules": {
                    "m01-api-gateway-shield": {"stream": STREAM_KEYS["api_calls"], "status": "consuming"},
                    "m05-sap-mcp-suite": {"stream": STREAM_KEYS["sap_mcp"], "status": "consuming"},
                    "m08-anomaly-detection": {"stream": STREAM_KEYS["anomalies"], "status": "consuming"},
                    "m04-zero-trust-fabric": {"stream": STREAM_KEYS["zero_trust"], "status": "consuming"},
                    "m06-credential-vault": {"stream": STREAM_KEYS["credentials"], "status": "consuming"},
                    "m12-rules-engine": {"stream": STREAM_KEYS["alerts"], "status": "consuming"},
                    "m15-multicloud-ispm": {"stream": STREAM_KEYS["cloud_posture"], "status": "consuming"},
                },
                "events_processed": state["events_processed"],
            })
            return

        with LOCK:
            alerts = list(ALERTS)[:limit]
            audit = list(AUDIT)[:limit]
            anomalies = list(ANOMALIES)[:limit]
            sap = list(SAP_EVENTS)[:limit]
            zt = list(ZERO_TRUST)[:limit]
            creds = list(CREDENTIALS)[:limit]
            cloud = list(CLOUD_POSTURE)[:limit]

        # ---- Existing endpoints ----
        if parsed.path == "/api/alerts":
            self._send_json(200, {"alerts": alerts})
            return
        if parsed.path == "/api/audit":
            self._send_json(200, {"rows": audit})
            return

        # ---- New module-specific endpoints ----
        if parsed.path == "/api/anomalies":
            self._send_json(200, {"anomalies": anomalies})
            return
        if parsed.path == "/api/sap-activity":
            self._send_json(200, {"events": sap})
            return
        if parsed.path == "/api/zero-trust":
            self._send_json(200, {"evaluations": zt})
            return
        if parsed.path == "/api/credentials":
            self._send_json(200, {"events": creds})
            return
        if parsed.path == "/api/cloud-posture":
            self._send_json(200, {"findings": cloud})
            return

        # ---- Dashboard stats (aggregate) ----
        if parsed.path == "/api/stats":
            critical = sum(1 for a in alerts if a.get("severity") == "critical")
            latencies = [a.get("latencyMs", 0) for a in alerts if "latencyMs" in a]
            avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0
            self._send_json(200, {
                "total_alerts": len(list(ALERTS)),
                "critical_alerts": critical,
                "avg_latency_ms": avg_lat,
                "anomalies_count": len(list(ANOMALIES)),
                "sap_events_count": len(list(SAP_EVENTS)),
                "zero_trust_evals": len(list(ZERO_TRUST)),
                "credential_events": len(list(CREDENTIALS)),
                "cloud_findings": len(list(CLOUD_POSTURE)),
            })
            return

        self._send_json(404, {"error": "not_found"})

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    thread = threading.Thread(target=stream_consumer_loop, daemon=True)
    thread.start()

    server = ThreadingHTTPServer(("0.0.0.0", 8787), Handler)
    print("=" * 60)
    print("IntegriShield SOC Dashboard Backend")
    print("=" * 60)
    print(f"  Listening:    http://localhost:8787")
    print(f"  Redis:        {REDIS_URL}")
    print(f"  Postgres:     {'configured' if DATABASE_URL else 'disabled'}")
    print(f"  Streams:      {len(STREAM_KEYS)} configured")
    for name, key in STREAM_KEYS.items():
        print(f"    {name:15s} → {key}")
    print("=" * 60)
    server.serve_forever()


if __name__ == "__main__":
    main()

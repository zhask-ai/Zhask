"""Multi-stream demo event producer — generates events for ALL module streams.

Exercises every dashboard panel by publishing diverse events to:
  - integrishield:api_call_events     (M01 — API calls)
  - integrishield:anomaly_scores      (M08 — anomaly detection)
  - integrishield:sap_mcp_events      (M05 — SAP MCP tools)
  - integrishield:zero_trust_events   (M04 — access decisions)
  - integrishield:credential_events   (M06 — vault operations)
  - integrishield:cloud_posture_events(M15 — cloud findings)

Usage:
  python scripts/demo_all_streams.py --redis-url redis://localhost:6379/0
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import redis


# ── Seed data loader ──
SEED_FILE = Path(__file__).resolve().parents[1] / "poc" / "seed" / "api_call_events.json"


def load_seed_events() -> list[dict]:
    if SEED_FILE.exists():
        with open(SEED_FILE) as f:
            return json.load(f)
    return []


SEED_EVENTS = load_seed_events()

# ── Event generators ──

def gen_api_call() -> dict:
    if SEED_EVENTS and random.random() < 0.4:
        base = random.choice(SEED_EVENTS).copy()
        base["event_id"] = str(uuid4())
        base["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        return base

    roll = random.randint(1, 100)
    event = {
        "event_id": str(uuid4()),
        "source_ip": f"10.42.0.{random.randint(2, 245)}",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    if roll <= 30:
        event.update(bytes_out=str(random.randint(11_000_000, 25_000_000)),
                     off_hours="false", unknown_endpoint="false")
    elif roll <= 60:
        event.update(bytes_out=str(random.randint(500, 5000)),
                     off_hours="true", unknown_endpoint="false")
    elif roll <= 85:
        event.update(bytes_out=str(random.randint(500, 5000)),
                     off_hours="false", unknown_endpoint="true")
    else:
        event.update(bytes_out=str(random.randint(100, 3000)),
                     off_hours="false", unknown_endpoint="false")
    return event


def gen_anomaly() -> dict:
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "anomaly_score": round(random.uniform(0.3, 0.99), 3),
        "baseline_deviation": round(random.uniform(1.5, 8.0), 2),
        "classification": random.choice(["time_anomaly", "volume_anomaly", "pattern_anomaly", "frequency_anomaly"]),
        "source_module": "m08-anomaly-detection",
    }


def gen_sap_mcp() -> dict:
    tools = [
        "RFC_READ_TABLE", "BAPI_USER_GET_DETAIL", "BAPI_MATERIAL_GETLIST",
        "RFC_SYSTEM_INFO", "BAPI_FLIGHT_GETLIST", "BAPI_VENDOR_GETLIST",
        "security_audit_query", "transport_log_check", "auth_object_scan",
    ]
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool_name": random.choice(tools),
        "result": random.choice(["success", "success", "success", "partial", "error"]),
        "source_module": "m05-sap-mcp-suite",
    }


def gen_zero_trust() -> dict:
    decision = random.choices(["allow", "deny", "challenge"], weights=[60, 20, 20])[0]
    controls = []
    if decision != "allow":
        controls = random.sample(["device_trust", "geo_policy", "mfa_required", "session_expired"],
                                  k=random.randint(1, 3))
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "user_id": f"user_{random.randint(100, 999)}",
        "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "decision": decision,
        "risk_score": str(random.randint(0, 100)),
        "failed_controls": ",".join(controls),
        "source_module": "m04-zero-trust-fabric",
    }


def gen_credential() -> dict:
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "key": random.choice(["sap_rfc_password", "db_master_key", "api_token_m01",
                               "vault_unseal_key", "tls_cert_m08", "oauth_client_secret"]),
        "action": random.choice(["rotated", "expiry_warning", "created", "accessed"]),
        "status": random.choice(["active", "active", "rotating", "expired"]),
        "tenant_id": f"tenant-{random.randint(1, 5)}",
        "source_module": "m06-credential-vault",
    }


def gen_cloud_posture() -> dict:
    providers = ["aws", "gcp", "azure"]
    controls = {
        "aws": ["S3.1", "IAM.2", "EC2.5", "RDS.3", "Lambda.1"],
        "gcp": ["GCE.1", "IAM.3", "GCS.2", "SQL.1", "KMS.1"],
        "azure": ["VM.2", "Storage.1", "AAD.3", "SQL.2", "KV.1"],
    }
    provider = random.choice(providers)
    return {
        "event_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "resource_id": f"arn:{provider}:resource-{random.randint(1000, 9999)}",
        "control_id": random.choice(controls[provider]),
        "risk_score": str(random.choice([25, 50, 75, 90])),
        "raw_severity": random.choice(["critical", "high", "medium", "low"]),
        "source_module": "m15-multicloud-ispm",
    }


# ── Stream mapping ──
GENERATORS = {
    "integrishield:api_call_events": gen_api_call,
    "integrishield:anomaly_scores": gen_anomaly,
    "integrishield:sap_mcp_events": gen_sap_mcp,
    "integrishield:zero_trust_events": gen_zero_trust,
    "integrishield:credential_events": gen_credential,
    "integrishield:cloud_posture_events": gen_cloud_posture,
}


def main():
    parser = argparse.ArgumentParser(description="Produce demo events to ALL IntegriShield streams.")
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--count", type=int, default=0, help="0 = run forever")
    args = parser.parse_args()

    client = redis.from_url(args.redis_url)
    sent = 0

    print("=" * 60)
    print("IntegriShield Multi-Stream Demo Producer")
    print("=" * 60)
    for stream in GENERATORS:
        print(f"  → {stream}")
    print(f"  interval: {args.interval}s | redis: {args.redis_url}")
    print("=" * 60)

    while True:
        # Each tick, produce to a random stream
        stream = random.choice(list(GENERATORS.keys()))
        payload = GENERATORS[stream]()

        # Redis XADD expects flat string values
        flat = {k: str(v) for k, v in payload.items()}
        entry_id = client.xadd(stream, flat)
        sent += 1

        sid = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
        print(f"[{sent:>5}] {stream.split(':')[-1]:25s} → {sid}")

        if args.count > 0 and sent >= args.count:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

"""
POC seed injector — publishes synthetic RFC events to Redis for live demo.

Injects a mix of normal events and all 3 anomaly scenarios:
  1. Off-hours RFC call
  2. Bulk extraction (RFC_READ_TABLE, 80k rows)
  3. Shadow endpoint (unknown RFC function)

Run via docker-compose seed-injector service, or directly:
  REDIS_URL=redis://localhost:6379 python poc/seed-injector/inject.py
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
INJECT_DELAY_MS = int(os.getenv("INJECT_DELAY_MS", "200"))
STREAM = "rfc_events"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _off_hours_ts() -> str:
    """Return a timestamp at 2:30am today."""
    now = datetime.now(timezone.utc)
    return now.replace(hour=2, minute=30, second=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_normal_event() -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "rfc_function": "BAPI_CUSTOMER_GETLIST",
        "client_ip": "10.0.1.15",
        "user_id": "USR007",
        "timestamp": _now(),
        "rows_returned": "42",
        "response_time_ms": "310",
        "status": "SUCCESS",
        "sap_system": "PRD",
    }


def make_off_hours_event() -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "rfc_function": "BAPI_USER_GETLIST",
        "client_ip": "10.0.2.99",
        "user_id": "SVCACCT",
        "timestamp": _off_hours_ts(),
        "rows_returned": "215",
        "response_time_ms": "450",
        "status": "SUCCESS",
        "sap_system": "PRD",
    }


def make_bulk_extraction_event() -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "rfc_function": "RFC_READ_TABLE",
        "client_ip": "10.0.3.12",
        "user_id": "USR002",
        "timestamp": _now(),
        "rows_returned": "80000",
        "response_time_ms": "18500",
        "status": "SUCCESS",
        "sap_system": "PRD",
    }


def make_shadow_event() -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "rfc_function": "ZRFC_EXFIL_DATA",
        "client_ip": "10.0.1.77",
        "user_id": "USR013",
        "timestamp": _now(),
        "rows_returned": "1200",
        "response_time_ms": "890",
        "status": "SUCCESS",
        "sap_system": "PRD",
    }


DEMO_SEQUENCE = [
    # Warm up with normal traffic
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    # Scenario 1: Off-hours call
    ("off_hours", make_off_hours_event),
    # More normal
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    # Scenario 2: Bulk extraction
    ("bulk_extraction", make_bulk_extraction_event),
    # More normal
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    # Scenario 3: Shadow endpoint
    ("shadow_endpoint", make_shadow_event),
    # Tail off
    ("normal", make_normal_event),
    ("normal", make_normal_event),
    ("shadow_endpoint", make_shadow_event),  # same unknown fn called again
    ("normal", make_normal_event),
]


def main():
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    delay = INJECT_DELAY_MS / 1000.0

    print(f"Injecting {len(DEMO_SEQUENCE)} events into '{STREAM}' (delay={INJECT_DELAY_MS}ms)…")
    print()

    for scenario, factory in DEMO_SEQUENCE:
        event = factory()
        r.xadd(STREAM, event, maxlen=10_000, approximate=True)
        print(f"  [{scenario:>17}] {event['rfc_function']} rows={event['rows_returned']}")
        time.sleep(delay)

    print()
    print("All events injected. Check Redis streams:")
    print("  redis-cli XLEN anomaly_events")
    print("  redis-cli XLEN dlp_alerts")
    print("  redis-cli XLEN shadow_alerts")


if __name__ == "__main__":
    main()

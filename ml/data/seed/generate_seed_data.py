"""
Synthetic RFC event generator for POC training and demo injection.

Generates two outputs:
  ml/data/seed/normal_events.json   — 3 days of baseline traffic
  ml/data/seed/anomaly_events.json  — labelled anomaly events (all 3 types)

Run directly:
  python ml/data/seed/generate_seed_data.py

Or import generate_events() to publish directly to Redis for live demo.
"""

import json
import math
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Known SAP RFC functions (same list used by m11-shadow-integration)
# ---------------------------------------------------------------------------
KNOWN_RFC_FUNCTIONS = [
    "RFC_READ_TABLE",
    "BAPI_MATERIAL_GETLIST",
    "BAPI_CUSTOMER_GETLIST",
    "BAPI_SALESORDER_GETLIST",
    "BAPI_PO_GETDETAIL",
    "RFC_GET_SYSTEM_INFO",
    "SUSR_USER_AUTH_FOR_OBJ_GET",
    "BAPI_USER_GETLIST",
    "BAPI_COMPANYCODE_GETLIST",
    "RFC_FUNCTION_SEARCH",
    "BAPI_EMPLOYEE_GETDATA",
    "BAPI_VENDOR_GETLIST",
    "BAPI_PRODORD_GET_DETAIL",
    "RFC_PING",
    "STFC_CONNECTION",
]

# RFC functions that should never appear in production (used for shadow demo)
SHADOW_RFC_FUNCTIONS = [
    "UNKNOWN_BACKDOOR_FUNC",
    "ZRFC_EXFIL_DATA",
    "TEST_REXEC",
    "RFC_INTERNAL_DEBUG",
    "ZRFC_DUMP_USERS",
]

CLIENTS = [f"10.0.{random.randint(0,3)}.{i}" for i in range(10, 30)]
USERS = [f"USR{str(i).zfill(3)}" for i in range(1, 16)]

random.seed(42)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normal_event(dt: datetime) -> dict:
    """Generate a single normal RFC event during business hours."""
    rfc_fn = random.choice(KNOWN_RFC_FUNCTIONS)
    rows = int(random.expovariate(1 / 200))  # most calls return <200 rows
    rows = min(rows, 2000)
    return {
        "event_id": str(uuid.uuid4()),
        "rfc_function": rfc_fn,
        "client_ip": random.choice(CLIENTS),
        "user_id": random.choice(USERS),
        "timestamp": _ts(dt),
        "rows_returned": rows,
        "response_time_ms": max(50, int(random.gauss(300, 80))),
        "status": random.choices(["SUCCESS", "ERROR"], weights=[97, 3])[0],
        "sap_system": "PRD",
        "label": "normal",
    }


def generate_normal_events(start: datetime, days: int = 3) -> list[dict]:
    """Generate ~3 days of realistic business-hours traffic."""
    events = []
    for d in range(days):
        base_day = start + timedelta(days=d)
        if base_day.weekday() >= 5:
            continue  # skip weekends in baseline
        # ~80 calls per business hour (08:00–18:00)
        for hour in range(8, 18):
            calls_this_hour = int(random.gauss(80, 15))
            for _ in range(max(calls_this_hour, 20)):
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                dt = base_day.replace(hour=hour, minute=minute, second=second)
                events.append(_normal_event(dt))
    return events


def generate_anomaly_events(start: datetime) -> list[dict]:
    """Generate labelled anomaly events for all 3 POC scenarios."""
    anomalies = []

    # --- Scenario 1: Off-hours RFC calls (2am–4am) ---
    for i in range(40):
        dt = start + timedelta(days=random.randint(0, 2))
        dt = dt.replace(hour=random.randint(2, 4), minute=random.randint(0, 59))
        ev = _normal_event(dt)
        ev["label"] = "off_hours"
        anomalies.append(ev)

    # --- Scenario 2: Bulk data extraction ---
    for i in range(40):
        dt = start + timedelta(
            days=random.randint(0, 2),
            hours=random.randint(8, 17),
            minutes=random.randint(0, 59),
        )
        ev = _normal_event(dt)
        ev["rfc_function"] = "RFC_READ_TABLE"
        ev["rows_returned"] = random.randint(50_000, 500_000)
        ev["response_time_ms"] = random.randint(8_000, 30_000)
        ev["label"] = "bulk_extraction"
        anomalies.append(ev)

    # --- Scenario 3: Shadow endpoint calls ---
    for i in range(40):
        dt = start + timedelta(
            days=random.randint(0, 2),
            hours=random.randint(8, 17),
            minutes=random.randint(0, 59),
        )
        ev = _normal_event(dt)
        ev["rfc_function"] = random.choice(SHADOW_RFC_FUNCTIONS)
        ev["label"] = "shadow_endpoint"
        anomalies.append(ev)

    return anomalies


def main():
    repo_root = Path(__file__).resolve().parents[3]
    out_dir = repo_root / "ml" / "data" / "seed"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Use a fixed Monday as start so weekday logic is predictable
    start = datetime(2026, 3, 30, 0, 0, 0, tzinfo=timezone.utc)

    print("Generating normal events…")
    normal = generate_normal_events(start, days=5)
    with open(out_dir / "normal_events.json", "w") as f:
        json.dump(normal, f, indent=2)
    print(f"  → {len(normal)} normal events written")

    print("Generating anomaly events…")
    anomalies = generate_anomaly_events(start)
    with open(out_dir / "anomaly_events.json", "w") as f:
        json.dump(anomalies, f, indent=2)
    print(f"  → {len(anomalies)} anomaly events written")


if __name__ == "__main__":
    main()

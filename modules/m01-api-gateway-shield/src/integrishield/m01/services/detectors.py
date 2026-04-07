"""
M01 — Detection Logic
----------------------
Three detectors that run synchronously on every intercepted RFC call
before the event is published to Redis.

Detector 1: Off-hours
  Uses shared.utils.time_utils.is_off_hours().
  Any call outside 06:00–22:00 UTC is flagged.
  Threshold configurable via BUSINESS_HOUR_START / BUSINESS_HOUR_END envvars
  (post-POC — for now the defaults in time_utils.py apply).

Detector 2: Bulk extraction
  rows_returned > BULK_ROW_THRESHOLD (default 10 000).
  Threshold configurable via BULK_ROW_THRESHOLD envvar.

Detector 3: Shadow endpoint
  rfc_function not in the known allowlist.
  Allowlist is a frozenset loaded from KNOWN_RFC_FUNCTIONS envvar
  (comma-separated) or falls back to a hard-coded POC seed list.
  M11 (Dev 2) publishes the formal shadow_alert event;
  M01 records the flag here for the audit log and the response body.

Owned by Dev 1.
"""

import os
from datetime import datetime
from functools import lru_cache

from shared.utils.time_utils import is_off_hours
from shared.telemetry import get_logger
from integrishield.m01.models.rfc_request import DetectionFlags

logger = get_logger(__name__)

# ── Thresholds ──────────────────────────────────────────────────────────────

_BULK_ROW_THRESHOLD = int(os.getenv("BULK_ROW_THRESHOLD", "10000"))

# Seed allowlist — the RFC functions that appeared in normal seed data.
# In production this list is managed in shared/schemas or a DB table.
_POC_KNOWN_FUNCTIONS: frozenset[str] = frozenset({
    "RFC_READ_TABLE",
    "BAPI_USER_GET_DETAIL",
    "BAPI_MATERIAL_GETLIST",
    "BAPI_SALESORDER_GETLIST",
    "BAPI_VENDOR_GETLIST",
    "BAPI_COMPANYCODE_GETLIST",
    "RFC_SYSTEM_INFO",
    "BAPI_FLIGHT_GETLIST",
    "BAPI_CUSTOMER_GETLIST",
    "STFC_CONNECTION",                 # connectivity test — always known
})


@lru_cache(maxsize=1)
def _known_functions() -> frozenset[str]:
    """
    Load the RFC function allowlist.
    Checks KNOWN_RFC_FUNCTIONS envvar first; falls back to POC seed list.
    """
    env_val = os.getenv("KNOWN_RFC_FUNCTIONS", "")
    if env_val.strip():
        custom = frozenset(fn.strip() for fn in env_val.split(",") if fn.strip())
        logger.info(
            "Loaded RFC allowlist from env",
            extra={"svc": "m01", "count": len(custom)},
        )
        return custom
    logger.info(
        "Using POC seed RFC allowlist",
        extra={"svc": "m01", "count": len(_POC_KNOWN_FUNCTIONS)},
    )
    return _POC_KNOWN_FUNCTIONS


# ── Detector functions ───────────────────────────────────────────────────────

def detect_off_hours(timestamp: datetime) -> bool:
    """Return True if *timestamp* falls outside business hours (UTC)."""
    return is_off_hours(timestamp)


def detect_bulk_extraction(rows_returned: int) -> bool:
    """Return True if *rows_returned* exceeds the bulk extraction threshold."""
    return rows_returned > _BULK_ROW_THRESHOLD


def detect_shadow_endpoint(rfc_function: str) -> bool:
    """Return True if *rfc_function* is NOT in the known allowlist."""
    return rfc_function not in _known_functions()


# ── Orchestrator ─────────────────────────────────────────────────────────────

def run_detectors(
    rfc_function: str,
    rows_returned: int,
    timestamp: datetime,
) -> DetectionFlags:
    """
    Run all three detectors and return a DetectionFlags instance.

    Called by the proxy route before publishing to Redis.
    Pure function — no I/O, no side effects, easy to unit test.

    Parameters
    ----------
    rfc_function  : SAP RFC function name
    rows_returned : number of rows returned by the RFC call
    timestamp     : UTC datetime of the call

    Returns
    -------
    DetectionFlags with all three flags set.
    """
    off_hours  = detect_off_hours(timestamp)
    bulk       = detect_bulk_extraction(rows_returned)
    shadow     = detect_shadow_endpoint(rfc_function)

    return DetectionFlags(
        is_off_hours=off_hours,
        is_bulk_extraction=bulk,
        is_shadow_endpoint=shadow,
        flagged_at=timestamp if (off_hours or bulk or shadow) else None,
    )

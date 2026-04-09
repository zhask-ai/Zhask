"""
IntegriShield POC — Mock SAP Backend
--------------------------------------
Simulates a minimal SAP RFC-over-HTTP gateway for local demo.

M01 forwards every intercepted RFC call to:
    POST http://mock-sap:8080/rfc/{function_name}

This service returns realistic-looking payloads so M01's proxy
route completes the full request lifecycle without needing a real
SAP system.

Scenario behaviour (driven by function name + request body):
──────────────────────────────────────────────────────────────
RFC_READ_TABLE          → returns rows_returned = BULK_ROWS (default 80 000)
                          triggers M01 bulk-extraction detector
BAPI_* / known fns      → returns rows_returned = 10–500 (normal traffic)
Z* / unknown fns        → returns rows_returned = 0–1 200 (shadow endpoint;
                          M01's allowlist check flags this, not mock-sap)
STFC_CONNECTION         → connectivity test, always 200 + 0 rows
Any fn + error=true     → simulates RFC_ERROR response (status=ERROR)

Owned by Dev 1 (poc/ folder).
"""

import os
import random
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Path
from pydantic import BaseModel

app = FastAPI(
    title="IntegriShield — Mock SAP Backend",
    description="Simulates SAP RFC-over-HTTP for POC demo.",
    version="0.1.0-poc",
)

# ── Config ────────────────────────────────────────────────────────────────────

BULK_ROWS        = int(os.getenv("MOCK_SAP_BULK_ROWS",   "80000"))
NORMAL_ROW_MAX   = int(os.getenv("MOCK_SAP_NORMAL_ROWS", "500"))
BASE_LATENCY_MS  = int(os.getenv("MOCK_SAP_LATENCY_MS",  "120"))   # added to every resp

# RFC functions the mock SAP treats as "normal" (not bulk)
_NORMAL_FUNCTIONS = {
    "BAPI_USER_GET_DETAIL",
    "BAPI_MATERIAL_GETLIST",
    "BAPI_SALESORDER_GETLIST",
    "BAPI_VENDOR_GETLIST",
    "BAPI_COMPANYCODE_GETLIST",
    "BAPI_FLIGHT_GETLIST",
    "BAPI_CUSTOMER_GETLIST",
    "STFC_CONNECTION",
}


# ── Models ────────────────────────────────────────────────────────────────────

class RFCRequest(BaseModel):
    """Body sent by M01 when forwarding a proxied RFC call."""
    user_id:    str | None = None
    sap_system: str | None = "PRD"
    error:      bool       = False   # force an error response for testing
    parameters: dict       = {}


class RFCResponse(BaseModel):
    rfc_function:    str
    status:          str
    rows_returned:   int
    response_time_ms: int
    sap_system:      str
    timestamp:       str
    data:            list[dict]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "mock-sap"}


@app.post("/rfc/{function_name}", response_model=RFCResponse)
def call_rfc(
    body: RFCRequest,
    function_name: str = Path(..., description="SAP RFC function module name"),
) -> RFCResponse:
    """
    Simulate an SAP RFC call.

    Latency is faked with time.sleep() so response_time_ms in the
    api_call_event reflects something realistic.
    """

    # Forced error path (used by integration tests)
    if body.error:
        raise HTTPException(status_code=500, detail=f"RFC_ERROR: {function_name} failed")

    # Determine rows_returned based on function type
    if function_name == "STFC_CONNECTION":
        rows = 0
        latency_ms = 20
    elif function_name == "RFC_READ_TABLE":
        rows = BULK_ROWS
        latency_ms = BASE_LATENCY_MS + random.randint(15_000, 20_000)
    elif function_name in _NORMAL_FUNCTIONS:
        rows = random.randint(10, NORMAL_ROW_MAX)
        latency_ms = BASE_LATENCY_MS + random.randint(50, 800)
    else:
        # Unknown / shadow function — SAP responds normally; M01 flags it
        rows = random.randint(0, 1200)
        latency_ms = BASE_LATENCY_MS + random.randint(100, 1000)

    # Simulate network + processing latency
    time.sleep(latency_ms / 1000.0)

    # Build a minimal synthetic result set
    data = [
        {"row": i, "value": f"RECORD_{i:05d}"}
        for i in range(min(rows, 5))   # return at most 5 sample rows in the payload
    ]

    return RFCResponse(
        rfc_function=function_name,
        status="SUCCESS",
        rows_returned=rows,
        response_time_ms=latency_ms,
        sap_system=body.sap_system or "PRD",
        timestamp=datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        data=data,
    )

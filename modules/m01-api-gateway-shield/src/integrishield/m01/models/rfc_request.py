"""
Pydantic request/response models for M01's proxy endpoint.

RFCProxyRequest  — body that callers send to POST /rfc/proxy
RFCProxyResponse — what M01 returns after forwarding to SAP backend
DetectionFlags   — internal model capturing what detectors flagged
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class RFCProxyRequest(BaseModel):
    """
    Body for POST /rfc/proxy.

    In production this would carry the full RFC call payload.
    For the POC it captures the fields M01 needs to (a) forward to
    the mock SAP backend and (b) build an api_call_event.
    """

    rfc_function: str = Field(
        ...,
        description="SAP RFC function module name, e.g. RFC_READ_TABLE",
        examples=["RFC_READ_TABLE", "BAPI_USER_GET_DETAIL"],
    )
    user_id: str = Field(
        ...,
        description="SAP user ID making the call",
        examples=["JDOE", "SVCACC01"],
    )
    sap_system: str | None = Field(
        default=None,
        description="SAP system ID (PRD, QA, DEV …)",
        examples=["PRD"],
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="RFC call parameters forwarded verbatim to the SAP backend",
    )


class RFCProxyResponse(BaseModel):
    """
    Response returned by M01 to the original caller.

    Mirrors what the SAP backend returned, plus metadata M01 added.
    """

    event_id: str = Field(description="UUID of the api_call_event published to Redis")
    rfc_function: str
    status: Literal["SUCCESS", "ERROR", "TIMEOUT"]
    rows_returned: int
    response_time_ms: int
    sap_response: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw response body from the SAP backend",
    )

    # Detection flags — visible in the response so the dashboard can
    # highlight flagged calls immediately without waiting for M08.
    is_off_hours: bool
    is_bulk_extraction: bool
    is_shadow_endpoint: bool


class DetectionFlags(BaseModel):
    """Internal model — populated by detectors.py before publishing."""

    is_off_hours: bool = False
    is_bulk_extraction: bool = False
    is_shadow_endpoint: bool = False
    flagged_at: datetime | None = None

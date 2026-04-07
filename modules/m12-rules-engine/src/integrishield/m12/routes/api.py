"""API routes — rules evaluation endpoints for M12 Rules Engine."""

from fastapi import APIRouter

from integrishield.m12.models import (
    AlertsListResponse,
    ApiCallEvent,
    EvaluateRequest,
    EvaluateResponse,
)
from integrishield.m12.services import evaluate_event

router = APIRouter(prefix="/api/v1/rules", tags=["rules-engine"])

# In-memory alert buffer (shared with the consumer loop in main.py)
_recent_alerts: list = []


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest):
    """Manually evaluate an event against detection rules."""
    event = ApiCallEvent(
        event_id=req.event_id,
        bytes_out=req.bytes_out,
        off_hours=req.off_hours,
        unknown_endpoint=req.unknown_endpoint,
        source_ip=req.source_ip,
    )
    alert = evaluate_event(event)
    if alert:
        _recent_alerts.insert(0, alert)
        if len(_recent_alerts) > 500:
            _recent_alerts.pop()
    return EvaluateResponse(alert=alert, matched=alert is not None)


@router.get("/alerts", response_model=AlertsListResponse)
async def list_alerts(limit: int = 50):
    """Return the most recent alerts."""
    capped = min(limit, 200)
    subset = _recent_alerts[:capped]
    return AlertsListResponse(alerts=subset, total=len(_recent_alerts))

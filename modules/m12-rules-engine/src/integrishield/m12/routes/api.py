"""API routes — rules evaluation endpoints for M12 Rules Engine."""

from fastapi import APIRouter

from integrishield.m12.models import (
    AlertsListResponse,
    EvaluateRequest,
    EvaluateResponse,
)
from integrishield.m12.services import alert_message, evaluate_event

router = APIRouter(prefix="/api/v1/rules", tags=["rules-engine"])

# In-memory alert buffer — shared with the consumer loop in main.py
_recent_alerts: list = []


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest):
    """Manually evaluate an event against all 8 detection rules."""
    event = req.model_dump()
    alert = evaluate_event(event)
    if alert:
        alert["message"] = alert_message(alert)
        _recent_alerts.insert(0, alert)
        if len(_recent_alerts) > 500:
            _recent_alerts.pop()
    return EvaluateResponse(alert=alert, matched=alert is not None)


@router.get("/alerts")
async def list_alerts(limit: int = 50):
    """Return the most recent alerts from the stream consumer and REST evaluations."""
    capped = min(limit, 200)
    subset = _recent_alerts[:capped]
    return {"alerts": subset, "total": len(_recent_alerts)}

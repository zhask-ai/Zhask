"""API routes — access evaluation endpoints for M04 Zero-Trust Fabric."""

from fastapi import APIRouter

from integrishield.m04.models import AccessRequest, AccessResult, PolicyStatsResponse
from integrishield.m04.services import evaluate_access

router = APIRouter(prefix="/api/v1/zero-trust", tags=["zero-trust"])

_evaluations: list[AccessResult] = []


@router.post("/evaluate", response_model=AccessResult)
async def evaluate(req: AccessRequest):
    """Evaluate an access request against zero-trust policies."""
    result = evaluate_access(req)
    _evaluations.insert(0, result)
    if len(_evaluations) > 1000:
        _evaluations.pop()
    return result


@router.get("/stats", response_model=PolicyStatsResponse)
async def stats():
    """Return aggregate policy evaluation statistics."""
    if not _evaluations:
        return PolicyStatsResponse()
    return PolicyStatsResponse(
        total_evaluations=len(_evaluations),
        denied=sum(1 for e in _evaluations if e.decision.value == "deny"),
        allowed=sum(1 for e in _evaluations if e.decision.value == "allow"),
        challenged=sum(1 for e in _evaluations if e.decision.value == "challenge"),
        avg_risk_score=round(
            sum(e.risk_score for e in _evaluations) / len(_evaluations), 1
        ),
    )

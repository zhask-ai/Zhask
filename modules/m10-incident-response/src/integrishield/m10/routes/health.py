"""Health routes for M10 Incident Response."""

from fastapi import APIRouter, Request

from integrishield.m10.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness(request: Request):
    store = request.app.state.store
    return HealthResponse(
        status="ok",
        redis_connected=request.app.state.redis_ok,
        db_connected=store.db_ok(),
        open_incidents=store.open_count(),
    )

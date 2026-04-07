"""Health routes for M07 Compliance Autopilot."""

from fastapi import APIRouter, Request

from integrishield.m07.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness(request: Request):
    engine = request.app.state.engine
    loader = request.app.state.loader
    return HealthResponse(
        status="ok",
        redis_connected=request.app.state.redis_ok,
        db_connected=engine.db_ok(),
        controls_loaded=loader.count,
    )

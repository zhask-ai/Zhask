"""Health routes for M05 SAP MCP Suite."""

from fastapi import APIRouter, Request

from integrishield.m05.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness(request: Request):
    registry = request.app.state.registry
    redis_ok = request.app.state.redis_ok
    return HealthResponse(
        status="ok" if redis_ok else "degraded",
        redis_connected=redis_ok,
        tools_registered=len(registry.list_tools()),
    )

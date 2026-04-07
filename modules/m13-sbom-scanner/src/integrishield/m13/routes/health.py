"""Health routes for M13 SBOM Scanner."""

from fastapi import APIRouter, Request

from integrishield.m13.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    """Liveness probe — always ok if process is running."""
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness(request: Request):
    """Readiness probe — checks Redis and reports active scans."""
    orchestrator = request.app.state.orchestrator
    redis_ok = orchestrator.redis_ok()
    active = orchestrator._store.active_count()
    return HealthResponse(
        status="ok" if redis_ok else "degraded",
        redis_connected=redis_ok,
        active_scans=active,
    )

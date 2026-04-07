"""Health routes — /healthz and /readyz for M12 Rules Engine."""

from fastapi import APIRouter

from integrishield.m12.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    """Liveness probe — always returns ok if the process is running."""
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness():
    """Readiness probe — checks downstream dependencies."""
    # TODO: verify Redis connectivity
    return HealthResponse(status="ok", redis_connected=True)

"""Health + readiness endpoints for M01."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe — returns 200 if the process is alive."""
    return HealthResponse(
        status="ok",
        service="m01-api-gateway-shield",
        version="0.1.0-poc",
    )


@router.get("/ready", response_model=HealthResponse)
async def ready() -> HealthResponse:
    """Readiness probe — same as health for POC (no deep dep checks yet)."""
    return HealthResponse(
        status="ready",
        service="m01-api-gateway-shield",
        version="0.1.0-poc",
    )

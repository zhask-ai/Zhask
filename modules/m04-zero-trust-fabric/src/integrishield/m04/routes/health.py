"""Health routes — /healthz and /readyz for M04 Zero-Trust Fabric."""

from fastapi import APIRouter

from integrishield.m04.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness():
    return HealthResponse(status="ok")

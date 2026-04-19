"""Health routes — /healthz and /readyz for M12 Rules Engine."""

import logging

from fastapi import APIRouter

from integrishield.m12.models import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])

# Injected by main.py lifespan so the health check shares the app's Redis client
_redis_client = None


def set_redis_client(client) -> None:
    global _redis_client
    _redis_client = client


@router.get("/healthz", response_model=HealthResponse)
async def liveness():
    """Liveness probe — always returns ok if the process is running."""
    return HealthResponse(status="ok")


@router.get("/readyz", response_model=HealthResponse)
async def readiness():
    """Readiness probe — verifies Redis connectivity."""
    connected = False
    if _redis_client is not None:
        try:
            await _redis_client.ping()
            connected = True
        except Exception:
            logger.warning("[m12] Redis ping failed during readiness check")

    status = "ok" if connected else "unavailable"
    return HealthResponse(status=status, redis_connected=connected)

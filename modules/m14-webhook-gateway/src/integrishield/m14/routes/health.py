"""Health endpoints for M14."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    note: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="m14-webhook-gateway",
        version="0.0.1-stub",
        note="POC stub — full implementation post-funding",
    )

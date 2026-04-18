"""Health endpoints for M14 Webhook Gateway."""

import os

from fastapi import APIRouter, Request

from integrishield.m14.models import HealthResponse, WebhookStatsResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    db_path = os.getenv("M14_DB_PATH", "/app/data/m14_webhooks.db")
    return HealthResponse(
        status="ok",
        service="m14-webhook-gateway",
        version="1.0.0",
        backend=f"sqlite:{db_path}",
    )


@router.get("/stats", response_model=WebhookStatsResponse)
async def stats(request: Request) -> WebhookStatsResponse:
    """Return delivery queue and subscription statistics."""
    raw = request.app.state.db.stats()
    return WebhookStatsResponse(**raw)

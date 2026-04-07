"""
M14 — Webhook Gateway  [POC STUB]
===================================
Receives outbound webhook calls from IntegriShield modules and forwards
them to external destinations (SIEM, Slack, PagerDuty, SOAR platforms).

POC status: STUB — health + placeholder routes only.
            Full build scheduled post-funding.

Full build will include:
  - Webhook fan-out: one IntegriShield event → N configured destinations
  - Retry queue (Redis-backed) with exponential back-off
  - Per-destination auth (Bearer, HMAC-SHA256 signature, mTLS)
  - Delivery receipt tracking in Postgres
  - Dead-letter queue for failed deliveries
  - Dev 4's dashboard shows delivery status per alert

Event flow (post-build):
  anomaly_events / dlp_alerts / shadow_alerts (Redis Streams)
      → M14 consumer
          → POST https://customer-siem.example.com/api/events
          → POST https://hooks.slack.com/services/...
          → POST https://events.pagerduty.com/v2/enqueue

Owned by Dev 1.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.telemetry import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("M14 Webhook Gateway starting (POC stub)", extra={"svc": "m14"})
    yield
    logger.info("M14 shutting down", extra={"svc": "m14"})


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M14 Webhook Gateway",
        description=(
            "**POC STUB** — Outbound webhook fan-out to SIEM / Slack / PagerDuty. "
            "Full implementation post-funding."
        ),
        version="0.0.1-stub",
        lifespan=lifespan,
    )

    from integrishield.m14.routes.health import router as health_router
    from integrishield.m14.routes.webhooks import router as webhook_router

    app.include_router(health_router)
    app.include_router(webhook_router, prefix="/webhooks")

    return app


app = create_app()

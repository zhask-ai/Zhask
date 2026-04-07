"""
M01 — API Gateway Shield
FastAPI application entry point.

Startup sequence:
  1. configure_logging()        — structured JSON logs from first line
  2. create_tables()            — idempotent Postgres table creation
  3. include routers            — /health, /rfc

Environment variables (see poc/.env.example):
  REDIS_URL                — redis://redis:6379
  DATABASE_URL             — postgresql://...
  SAP_BACKEND_URL          — http://mock-sap:8080  (POC) or real SAP gateway
  INTEGRISHIELD_API_KEYS   — comma-separated valid keys
  LOG_LEVEL                — INFO (default)
  BULK_ROW_THRESHOLD       — 10000 (rows that trigger bulk-extraction flag)

Owned by Dev 1.
"""

import os

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.telemetry import configure_logging, get_logger
from shared.db.session import create_tables

from integrishield.m01.routes.proxy import router as proxy_router
from integrishield.m01.routes.health import router as health_router

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup tasks before accepting traffic."""
    logger.info("M01 API Gateway Shield starting up", extra={"svc": "m01"})
    try:
        create_tables()
        logger.info("Postgres audit table ready", extra={"svc": "m01"})
    except Exception as exc:
        # Don't crash on DB failure during POC — log and continue.
        # M01 can still proxy and publish to Redis without DB.
        logger.warning(
            "DB init failed — audit writes disabled",
            extra={"svc": "m01", "err": str(exc)},
        )
    yield
    logger.info("M01 shutting down", extra={"svc": "m01"})


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M01 API Gateway Shield",
        description=(
            "Transparent proxy that intercepts SAP RFC calls, "
            "publishes api_call_event to Redis Streams, "
            "and writes every call to the audit log."
        ),
        version="0.1.0-poc",
        lifespan=lifespan,
    )

    # Dev 4 dashboard will be on a different origin during local POC.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],   # tighten post-POC
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(proxy_router, prefix="/rfc")

    return app


app = create_app()

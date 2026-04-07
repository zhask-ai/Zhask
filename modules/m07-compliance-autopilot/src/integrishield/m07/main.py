"""FastAPI app factory + lifespan for M07 Compliance Autopilot."""

from __future__ import annotations

import logging
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import redis as redis_lib
import uvicorn
from fastapi import FastAPI

from integrishield.m07.config import settings
from integrishield.m07.routes.api import router as api_router
from integrishield.m07.routes.health import router as health_router
from integrishield.m07.services.compliance_engine import ComplianceEngine
from integrishield.m07.services.control_loader import ControlLoader
from integrishield.m07.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

_SHARED_PATH = Path(__file__).resolve().parents[7] / "shared"
if str(_SHARED_PATH) not in sys.path:
    sys.path.insert(0, str(_SHARED_PATH))


def _start_consumer_threads(engine: ComplianceEngine, redis_client) -> None:
    try:
        from integrishield.m07.services.consumer import ComplianceConsumer
    except ImportError:
        logger.warning("m07 consumer imports failed — no background consumers started")
        return

    streams = [s.strip() for s in settings.consume_streams.split(",") if s.strip()]

    for idx, stream in enumerate(streams):
        consumer = ComplianceConsumer(
            redis_url=settings.redis_url,
            stream_name=stream,
            consumer_name=f"{settings.consumer_name}-{idx}",
            group_name=settings.consumer_group,
            engine=engine,
            publisher=redis_client,
        )
        t = threading.Thread(target=consumer.run, daemon=True, name=f"m07-consumer-{idx}")
        t.start()
        logger.info("m07 consumer started for stream: %s", stream)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[m07] starting {settings.service_name} on {settings.host}:{settings.port}")

    # Load controls
    loader = ControlLoader(settings.controls_config_path)
    count = loader.load()
    logger.info("m07 loaded %d controls", count)

    # Connect Redis
    redis_client: redis_lib.Redis | None = None
    redis_ok = False
    try:
        redis_client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
        redis_client.ping()
        redis_ok = True
        logger.info("m07 Redis connected")
    except Exception as exc:
        logger.warning("m07 Redis unavailable: %s", exc)

    # Initialise engine
    engine = ComplianceEngine(loader=loader, redis_client=redis_client)
    engine.connect_db(settings.database_url)

    generator = ReportGenerator(engine=engine)

    app.state.loader = loader
    app.state.engine = engine
    app.state.generator = generator
    app.state.redis_ok = redis_ok

    _start_consumer_threads(engine, redis_client)

    yield

    print(f"[m07] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M07 Compliance Autopilot",
        description=(
            "Continuous SOX, SOC2, ISO 27001, and GDPR compliance monitoring. "
            "Automatically collects evidence from the IntegriShield event bus and "
            "generates downloadable compliance reports."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(api_router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m07.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

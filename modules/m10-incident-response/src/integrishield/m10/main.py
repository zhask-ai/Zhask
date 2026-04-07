"""FastAPI app factory + lifespan for M10 Incident Response."""

from __future__ import annotations

import logging
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import redis as redis_lib
import uvicorn
from fastapi import FastAPI

from integrishield.m10.config import settings
from integrishield.m10.routes.api import playbook_router, router as api_router
from integrishield.m10.routes.health import router as health_router
from integrishield.m10.services.incident_store import IncidentStore
from integrishield.m10.services.playbook_engine import PlaybookEngine

logger = logging.getLogger(__name__)

_SHARED_PATH = Path(__file__).resolve().parents[7] / "shared"
if str(_SHARED_PATH) not in sys.path:
    sys.path.insert(0, str(_SHARED_PATH))


def _start_consumer_threads(store: IncidentStore, engine: PlaybookEngine, redis_client) -> None:
    try:
        from integrishield.m10.services.consumer import AlertConsumer
    except ImportError:
        logger.warning("m10 consumer imports failed — no background consumers started")
        return

    streams = [
        settings.consume_alert_stream,
        settings.consume_anomaly_stream,
        settings.consume_dlp_stream,
    ]

    for idx, stream in enumerate(streams):
        consumer = AlertConsumer(
            redis_url=settings.redis_url,
            stream_name=stream,
            consumer_name=f"{settings.consumer_name}-{idx}",
            group_name=settings.consumer_group,
            store=store,
            engine=engine,
            redis_publisher=redis_client,
        )
        t = threading.Thread(target=consumer.run, daemon=True, name=f"m10-consumer-{idx}")
        t.start()
        logger.info("m10 consumer started for stream: %s", stream)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[m10] starting {settings.service_name} on {settings.host}:{settings.port}")

    store = IncidentStore()
    store.connect_db(settings.database_url)

    engine = PlaybookEngine()

    redis_client: redis_lib.Redis | None = None
    redis_ok = False
    try:
        redis_client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
        redis_client.ping()
        redis_ok = True
        logger.info("m10 Redis connected")
    except Exception as exc:
        logger.warning("m10 Redis unavailable: %s", exc)

    app.state.store = store
    app.state.engine = engine
    app.state.redis_ok = redis_ok

    _start_consumer_threads(store, engine, redis_client)

    yield

    print(f"[m10] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M10 Incident Response",
        description=(
            "Automated incident lifecycle management and playbook orchestration for SAP security events. "
            "Converts alerts from the rules engine into tracked incidents with automated response actions."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(api_router)
    app.include_router(playbook_router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m10.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

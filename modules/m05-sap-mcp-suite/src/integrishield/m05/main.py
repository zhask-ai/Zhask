"""FastAPI app factory + lifespan for M05 SAP MCP Suite."""

from __future__ import annotations

import logging
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import redis as redis_lib
import uvicorn
from fastapi import FastAPI

from integrishield.m05.config import settings
from integrishield.m05.routes.api import router as api_router
from integrishield.m05.routes.health import router as health_router
from integrishield.m05.services.event_cache import EventCache
from integrishield.m05.services.mcp_registry import McpToolRegistry

logger = logging.getLogger(__name__)

# Resolve path to shared/ so consumer can import RedisStreamConsumer
_REPO_ROOT = Path(__file__).resolve().parents[7]
_SHARED_PATH = _REPO_ROOT / "shared"
if str(_SHARED_PATH) not in sys.path:
    sys.path.insert(0, str(_SHARED_PATH))


def _start_consumer_threads(cache: EventCache) -> list[threading.Thread]:
    """Start one consumer thread per watched stream."""
    try:
        from shared.event_bus.consumer import RedisStreamConsumer  # type: ignore
    except ImportError:
        logger.warning("shared.event_bus.consumer not found — running without stream consumers")
        return []

    from integrishield.m05.services.consumer import SapMcpConsumer

    threads = []
    stream_names = [s.strip() for s in settings.consume_streams.split(",") if s.strip()]

    for idx, stream in enumerate(stream_names):
        consumer = SapMcpConsumer(
            redis_url=settings.redis_url,
            stream_name=stream,
            consumer_name=f"{settings.consumer_name}-{idx}",
            group_name=settings.consumer_group,
            cache=cache,
        )
        t = threading.Thread(target=consumer.run, daemon=True, name=f"m05-consumer-{idx}")
        t.start()
        threads.append(t)
        logger.info("m05 consumer thread started for stream: %s", stream)

    return threads


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[m05] starting {settings.service_name} on {settings.host}:{settings.port}")

    # Initialise cache and registry
    cache = EventCache(max_size=settings.event_cache_size)

    # Connect Redis
    redis_client: redis_lib.Redis | None = None
    redis_ok = False
    try:
        redis_client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
        redis_client.ping()
        redis_ok = True
        logger.info("m05 Redis connected")
    except Exception as exc:
        logger.warning("m05 Redis unavailable: %s", exc)

    registry = McpToolRegistry(cache=cache, redis_client=redis_client)

    app.state.cache = cache
    app.state.registry = registry
    app.state.redis_ok = redis_ok

    # Start consumer threads
    _start_consumer_threads(cache)

    yield

    print(f"[m05] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M05 SAP MCP Suite",
        description=(
            "MCP server exposing SAP security data as Claude-callable tools. "
            "Provides real-time event cache, anomaly scores, alerts, and inline rule evaluation."
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
        "integrishield.m05.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

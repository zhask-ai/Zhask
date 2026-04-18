"""FastAPI app factory + lifespan for M14 Webhook Gateway."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (env-driven, no pydantic-settings dep for this module)
# ---------------------------------------------------------------------------
REDIS_URL = os.getenv("M14_REDIS_URL", "redis://localhost:6379/0")
DB_PATH = os.getenv("M14_DB_PATH", "/app/data/m14_webhooks.db")
CONSUMER_STREAMS = os.getenv(
    "M14_CONSUMER_STREAMS",
    "integrishield:alerts,integrishield:incidents,integrishield:compliance_events",
)
CONSUMER_GROUP = "m14-webhook-gateway"
CONSUMER_NAME = "m14-dispatcher-1"


# ---------------------------------------------------------------------------
# Background stream consumer (runs in a daemon thread)
# ---------------------------------------------------------------------------

def _start_stream_consumer(app: FastAPI) -> threading.Thread:
    """Launch a Redis Streams consumer thread that feeds the dispatcher."""
    import redis as redis_lib  # noqa: PLC0415

    streams = [s.strip() for s in CONSUMER_STREAMS.split(",") if s.strip()]

    def _consume() -> None:
        try:
            r = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
            for stream in streams:
                try:
                    r.xgroup_create(stream, CONSUMER_GROUP, id="$", mkstream=True)
                except redis_lib.ResponseError as exc:
                    if "BUSYGROUP" not in str(exc):
                        raise

            logger.info("m14 consumer listening on streams: %s", streams)
            while True:
                messages = r.xreadgroup(
                    groupname=CONSUMER_GROUP,
                    consumername=CONSUMER_NAME,
                    streams={s: ">" for s in streams},
                    count=50,
                    block=1000,
                )
                if not messages:
                    continue
                for stream_name, event_list in messages:
                    for event_id, raw in event_list:
                        _handle_stream_event(app, stream_name, event_id, raw, r)
        except Exception as exc:
            logger.error("m14 consumer thread exited: %s", exc)

    t = threading.Thread(target=_consume, daemon=True, name="m14-consumer")
    t.start()
    return t


def _handle_stream_event(
    app: FastAPI,
    stream_name: str,
    event_id: str,
    raw: dict[str, str],
    r: Any,
) -> None:
    try:
        # Events are stored as {"data": "<json>"} by the shared producer
        data_str = raw.get("data", "{}")
        payload: dict[str, Any] = json.loads(data_str) if isinstance(data_str, str) else raw

        # Infer event type from stream name suffix
        event_type = stream_name.rsplit(":", 1)[-1]  # e.g. "alerts"

        # Dispatch to all matching subscriptions via the async dispatcher
        # We schedule on the running event loop from the main thread
        loop = app.state.loop
        asyncio.run_coroutine_threadsafe(
            app.state.dispatcher.dispatch(event_id, event_type, payload),
            loop,
        )
        r.xack(stream_name, CONSUMER_GROUP, event_id)
    except Exception:
        logger.exception("m14 failed to handle event %s from %s", event_id, stream_name)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    from integrishield.m14.db import WebhookDB  # noqa: PLC0415
    from integrishield.m14.services.dispatcher import Dispatcher  # noqa: PLC0415

    db = WebhookDB(DB_PATH)
    dispatcher = Dispatcher(db=db, redis_url=REDIS_URL)
    dispatcher.connect_redis()

    app.state.db = db
    app.state.dispatcher = dispatcher
    app.state.loop = asyncio.get_event_loop()

    consumer_thread = _start_stream_consumer(app)
    logger.info("M14 Webhook Gateway started (db=%s streams=%s)", DB_PATH, CONSUMER_STREAMS)

    yield

    logger.info("M14 shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M14 Webhook Gateway",
        description=(
            "Outbound webhook fan-out to SIEM / Slack / PagerDuty / SOAR. "
            "Subscriber registry, HMAC signing, exponential-backoff retry, DLQ."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    from integrishield.m14.routes.health import router as health_router  # noqa: PLC0415
    from integrishield.m14.routes.webhooks import router as webhook_router  # noqa: PLC0415

    app.include_router(health_router)
    app.include_router(webhook_router, prefix="/webhooks")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn  # noqa: PLC0415

    uvicorn.run(
        "integrishield.m14.main:app",
        host="0.0.0.0",
        port=8014,
        log_level="info",
        reload=False,
    )

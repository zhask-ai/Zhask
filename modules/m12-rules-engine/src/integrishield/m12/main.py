"""FastAPI app factory + lifespan for M12 Rules Engine."""

import asyncio
import json
import logging
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import uvicorn
from fastapi import FastAPI

from integrishield.m12.config import settings
from integrishield.m12.routes.api import _recent_alerts, router as api_router
from integrishield.m12.routes.health import router as health_router, set_redis_client
from integrishield.m12.services import alert_message, evaluate_event

logger = logging.getLogger(__name__)


async def _consume_loop(client: aioredis.Redis) -> None:
    """Consume api_call_events, evaluate rules, and publish alert_events."""
    stream = settings.consume_stream
    group = settings.consumer_group
    consumer = settings.consumer_name
    publish_stream = settings.publish_stream

    # Create consumer group if it doesn't already exist
    try:
        await client.xgroup_create(stream, group, id="$", mkstream=True)
    except Exception:
        pass  # BUSYGROUP or stream already exists — both are fine

    logger.info("[m12] consumer loop started on %s / group=%s", stream, group)

    while True:
        try:
            results = await client.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={stream: ">"},
                count=10,
                block=2000,
            )
            if not results:
                continue

            for _stream_name, messages in results:
                for msg_id, fields in messages:
                    try:
                        decoded = {
                            (k.decode() if isinstance(k, bytes) else k):
                            (v.decode() if isinstance(v, bytes) else v)
                            for k, v in fields.items()
                        }
                        # Event may be JSON-wrapped under "data" key
                        if "data" in decoded:
                            try:
                                decoded = {**decoded, **json.loads(decoded["data"])}
                            except (json.JSONDecodeError, TypeError):
                                pass

                        alert = evaluate_event(decoded)
                        if alert:
                            alert["message"] = alert_message(alert)
                            # Buffer for REST API
                            _recent_alerts.insert(0, alert)
                            if len(_recent_alerts) > settings.max_alerts_buffer:
                                _recent_alerts.pop()
                            # Publish to alert stream
                            await client.xadd(
                                publish_stream,
                                {k: str(v) for k, v in alert.items()},
                                maxlen=1000,
                                approximate=True,
                            )
                            logger.info("[m12] alert published: %s", alert.get("scenario"))
                    except Exception:
                        logger.exception("[m12] error processing message %s", msg_id)
                    finally:
                        await client.xack(stream, group, msg_id)

        except asyncio.CancelledError:
            logger.info("[m12] consumer loop cancelled — shutting down")
            break
        except Exception:
            logger.exception("[m12] consumer loop error — retrying in 5s")
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle hooks."""
    logger.info("[m12] starting %s on %s:%s", settings.service_name, settings.host, settings.port)

    client = aioredis.from_url(settings.redis_url, decode_responses=False)
    set_redis_client(client)

    consumer_task = asyncio.create_task(_consume_loop(client))
    try:
        yield
    finally:
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
        await client.aclose()
        logger.info("[m12] shutting down %s", settings.service_name)


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    app = FastAPI(
        title="IntegriShield — M12 Rules Engine",
        description="Evaluates api_call_events against 8 detection rules and publishes alert_events.",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(api_router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m12.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

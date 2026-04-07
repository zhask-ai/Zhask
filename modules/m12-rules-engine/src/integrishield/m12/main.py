"""FastAPI app factory + lifespan for M12 Rules Engine."""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from integrishield.m12.config import settings
from integrishield.m12.routes.api import router as api_router
from integrishield.m12.routes.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle hooks."""
    # TODO: start Redis Streams consumer as background task
    print(f"[m12] starting {settings.service_name} on {settings.host}:{settings.port}")
    yield
    print(f"[m12] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    app = FastAPI(
        title="IntegriShield — M12 Rules Engine",
        description="Evaluates events against detection rules for 3 POC scenarios: "
        "bulk-extraction, off-hours RFC, and shadow endpoint.",
        version="0.1.0",
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

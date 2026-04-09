"""FastAPI app factory + lifespan for M15 Multi-Cloud ISPM."""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from integrishield.m15.config import settings
from integrishield.m15.routes.api import router as api_router
from integrishield.m15.routes.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[m15] starting {settings.service_name} on {settings.host}:{settings.port}")
    yield
    print(f"[m15] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M15 Multi-Cloud ISPM",
        description="Normalize and score cloud security findings across AWS, GCP, Azure.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(api_router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m15.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

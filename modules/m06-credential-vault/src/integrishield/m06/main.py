"""FastAPI app factory + lifespan for M06 Credential Vault."""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from integrishield.m06.config import settings
from integrishield.m06.routes.api import router as api_router
from integrishield.m06.routes.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[m06] starting {settings.service_name} on {settings.host}:{settings.port}")
    yield
    print(f"[m06] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M06 Credential Vault",
        description="Secret storage, rotation lifecycle, and credential health monitoring.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(api_router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m06.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

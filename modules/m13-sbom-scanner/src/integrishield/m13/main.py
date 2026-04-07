"""FastAPI app factory + lifespan for M13 SBOM Scanner."""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from integrishield.m13.config import settings
from integrishield.m13.routes.api import router as api_router
from integrishield.m13.routes.health import router as health_router
from integrishield.m13.services.scan_orchestrator import ScanOrchestrator
from integrishield.m13.services.scan_store import ScanStore
from integrishield.m13.services.scanners import dependency_extractor


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    print(f"[m13] starting {settings.service_name} on {settings.host}:{settings.port}")

    # Initialise scan store + orchestrator
    store = ScanStore(max_size=settings.scan_store_max_size)
    orchestrator = ScanOrchestrator(store=store)

    # Load CVE stubs
    dependency_extractor.load_cve_stubs(settings.cve_stubs_path)

    # Connect Redis (non-fatal if unavailable in dev)
    orchestrator.connect_redis()

    app.state.orchestrator = orchestrator

    yield

    print(f"[m13] shutting down {settings.service_name}")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M13 SBOM Scanner",
        description=(
            "Static analysis and CycloneDX 1.4 SBOM generation for SAP ABAP custom code. "
            "Detects hardcoded credentials, SQL injection, insecure RFC calls, and known CVEs."
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
        "integrishield.m13.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )

"""FastAPI app factory + lifespan for M13 SBOM Scanner."""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import BackgroundTasks, FastAPI

from integrishield.m13.config import settings
from integrishield.m13.feeds.cache import CVECache
from integrishield.m13.feeds.nvd import NVDFeed
from integrishield.m13.feeds.osv import OSVFeed
from integrishield.m13.routes.api import router as api_router
from integrishield.m13.routes.health import router as health_router
from integrishield.m13.services.scan_orchestrator import ScanOrchestrator
from integrishield.m13.services.scan_store import ScanStore
from integrishield.m13.services.scanners import dependency_extractor


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    print(f"[m13] starting {settings.service_name} on {settings.host}:{settings.port}")

    store = ScanStore(max_size=settings.scan_store_max_size)
    orchestrator = ScanOrchestrator(store=store)

    # Initialise CVE feeds
    cache = CVECache(settings.cve_cache_db_path, ttl_hours=settings.cve_cache_ttl_hours)
    nvd = NVDFeed(api_key=settings.nvd_api_key, search_prefix=settings.nvd_search_prefix)
    osv = OSVFeed(ecosystem=settings.osv_ecosystem)

    # Wire feeds into the dependency extractor
    dependency_extractor.init_feeds(cache=cache, nvd=nvd, osv=osv)

    # Legacy stub path — seeds cache from stubs file if it exists (graceful)
    dependency_extractor.load_cve_stubs(settings.cve_stubs_path)

    orchestrator.connect_redis()

    app.state.orchestrator = orchestrator
    app.state.cve_cache = cache
    app.state.nvd_feed = nvd
    app.state.osv_feed = osv

    yield

    print(f"[m13] shutting down {settings.service_name}")


def _cve_router():
    """Admin router for CVE cache management."""
    from fastapi import APIRouter, Request  # noqa: PLC0415

    router = APIRouter(prefix="/api/v1/cve", tags=["cve-cache"])

    @router.post("/refresh")
    async def refresh_cve_cache(
        request: Request,
        background_tasks: BackgroundTasks,
        components: list[str] | None = None,
    ):
        """
        Trigger NVD/OSV refresh for a list of component names.
        Pass an empty list to invalidate the entire cache (next scan re-fetches lazily).
        """
        cache: CVECache = request.app.state.cve_cache
        nvd: NVDFeed = request.app.state.nvd_feed
        osv: OSVFeed = request.app.state.osv_feed

        if not components:
            removed = cache.invalidate()
            return {
                "action": "full_invalidation",
                "entries_removed": removed,
                "note": "Cache cleared — next scan fetches live CVEs from NVD/OSV.",
            }

        def _do_refresh() -> None:
            for comp in components:
                cves = nvd.lookup(comp)
                if not cves:
                    cves = osv.lookup(comp)
                source = "nvd" if (cves and cves[0].get("source") == "nvd") else "osv"
                cache.put(comp, cves, source=source)

        background_tasks.add_task(_do_refresh)
        return {
            "action": "refresh_scheduled",
            "components": components,
            "note": "CVE refresh running in background.",
        }

    @router.get("/cache/stats")
    async def cache_stats(request: Request):
        """Return CVE cache statistics."""
        return request.app.state.cve_cache.stats()

    return router


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M13 SBOM Scanner",
        description=(
            "Static analysis and CycloneDX 1.4 SBOM generation for SAP ABAP custom code. "
            "Detects hardcoded credentials, SQL injection, insecure RFC calls, and live CVEs "
            "via NVD 2.0 + OSV.dev with SQLite cache."
        ),
        version="0.2.0",
        lifespan=lifespan,
    )
    app.include_router(health_router)
    app.include_router(api_router)
    app.include_router(_cve_router())
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

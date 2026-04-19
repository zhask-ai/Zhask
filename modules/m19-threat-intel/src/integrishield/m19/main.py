"""m19-threat-intel — fuse CISA KEV, EPSS, OSV, SAP Security Notes."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException

from shared.auth.middleware import AuthMiddleware

from .feeds import fuse

_CACHE: dict[str, dict[str, Any]] = {}
_SOURCES: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()


def _refresh() -> dict[str, Any]:
    records = fuse()
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        _CACHE.clear()
        for r in records:
            _CACHE[r["cve_id"]] = r
        for src in {"cisa-kev", "epss", "sap-notes"}:
            _SOURCES[src] = {"last_pulled_at": now, "success": True}
    return {"refreshed": len(_CACHE), "at": now}


def create_app() -> FastAPI:
    app = FastAPI(title="IntegriShield M19 — Threat Intel", version="0.1.0")
    app.add_middleware(AuthMiddleware)
    _refresh()

    @app.get("/health")
    def health():
        return {"status": "ok", "module": "m19-threat-intel", "cached_cves": len(_CACHE)}

    @app.post("/intel/refresh")
    def refresh():
        return _refresh()

    @app.get("/intel/feeds/status")
    def feeds_status():
        return {"sources": _SOURCES, "cached_cves": len(_CACHE)}

    @app.get("/intel/cve/{cve_id}")
    def get_cve(cve_id: str):
        rec = _CACHE.get(cve_id.upper())
        if not rec:
            raise HTTPException(404, f"CVE {cve_id} not in intel cache")
        return rec

    @app.get("/intel/cves")
    def list_cves(kev: bool | None = None, min_epss: float | None = None):
        items = list(_CACHE.values())
        if kev is not None:
            items = [x for x in items if bool(x.get("kev")) == kev]
        if min_epss is not None:
            items = [x for x in items if (x.get("epss") or 0) >= min_epss]
        items.sort(key=lambda x: x.get("epss") or 0, reverse=True)
        return {"count": len(items), "cves": items}

    @app.post("/intel/enrich")
    def enrich(cve_ids: list[str]):
        out = []
        for cve in cve_ids:
            rec = _CACHE.get(cve.upper())
            if rec:
                out.append(rec)
            else:
                out.append({"cve_id": cve.upper(), "kev": False, "sources": [], "unknown": True})
        return {"count": len(out), "enriched": out}

    return app


app = create_app()

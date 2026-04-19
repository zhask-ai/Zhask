"""m18-ledger — Tamper-Evident Audit Ledger.

Accepts events from other modules, appends them to a per-tenant hash chain,
periodically emits signed Merkle anchors, and exposes verification endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from shared.audit.ledger import verify_chain
from shared.auth.middleware import AuthMiddleware
from shared.auth.tenant import DEFAULT_POC_TENANT

from .store import get_store


def _tenant(request: Request) -> str:
    return (request.scope.get("state") or {}).get("tenant_id") or DEFAULT_POC_TENANT


class AppendRequest(BaseModel):
    event_type: str
    payload: dict[str, Any]


def create_app() -> FastAPI:
    app = FastAPI(title="IntegriShield M18 — Ledger", version="0.1.0")
    app.add_middleware(AuthMiddleware)
    store = get_store()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "module": "m18-ledger"}

    @app.post("/ledger/append")
    def append(req: AppendRequest, tenant_id: str = Depends(_tenant)) -> dict[str, Any]:
        e = store.append(tenant_id, req.event_type, req.payload)
        return {
            "seq": e.seq,
            "hash": e.hash,
            "prev_hash": e.prev_hash,
            "timestamp": e.timestamp,
        }

    @app.get("/ledger/entries")
    def list_entries(
        start: int = 1,
        end: int | None = None,
        tenant_id: str = Depends(_tenant),
    ) -> dict[str, Any]:
        items = store.range(tenant_id, start, end)
        return {
            "tenant_id": tenant_id,
            "count": len(items),
            "entries": [
                {
                    "seq": e.seq,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "prev_hash": e.prev_hash,
                    "hash": e.hash,
                    "payload": e.payload,
                }
                for e in items
            ],
        }

    @app.post("/ledger/anchor")
    def anchor(tenant_id: str = Depends(_tenant)) -> dict[str, Any]:
        return store.anchor(tenant_id)

    @app.get("/ledger/anchors")
    def anchors(tenant_id: str = Depends(_tenant)) -> dict[str, Any]:
        return {"tenant_id": tenant_id, "anchors": store.anchors(tenant_id)}

    @app.post("/ledger/verify")
    def verify(tenant_id: str = Depends(_tenant)) -> dict[str, Any]:
        items = store.range(tenant_id)
        ok, bad = verify_chain(items)
        if not ok:
            raise HTTPException(
                status_code=409,
                detail={"valid": False, "broken_at_index": bad, "entries_checked": len(items)},
            )
        return {"valid": True, "entries_checked": len(items)}

    return app


app = create_app()

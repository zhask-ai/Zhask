"""m17-sod-analyzer — SAP Segregation of Duties violation graph."""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import asdict

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from shared.auth.middleware import AuthMiddleware
from shared.auth.tenant import DEFAULT_POC_TENANT

from .engine import Violation, evaluate_user, load_risks

_RISKS = load_risks()
_ROLE_MAP: dict[tuple[str, str], list[str]] = {}
_USER_ROLES: dict[tuple[str, str], list[str]] = {}
_VIOLATIONS: dict[str, list[Violation]] = defaultdict(list)
_LOCK = threading.Lock()


def _tenant(request: Request) -> str:
    return (request.scope.get("state") or {}).get("tenant_id") or DEFAULT_POC_TENANT


class RoleMapIn(BaseModel):
    role: str
    tcodes: list[str]


class UserRolesIn(BaseModel):
    sap_user: str
    roles: list[str]


def create_app() -> FastAPI:
    app = FastAPI(title="IntegriShield M17 — SoD Analyzer", version="0.1.0")
    app.add_middleware(AuthMiddleware)

    @app.get("/health")
    def health():
        return {"status": "ok", "module": "m17-sod-analyzer", "risks_loaded": len(_RISKS)}

    @app.get("/sod/risks")
    def risks():
        return {"count": len(_RISKS), "risks": [asdict(r) for r in _RISKS]}

    @app.post("/sod/role-map")
    def upsert_role_map(item: RoleMapIn, tenant_id: str = Depends(_tenant)):
        with _LOCK:
            _ROLE_MAP[(tenant_id, item.role)] = sorted(set(item.tcodes))
        return {"tenant_id": tenant_id, "role": item.role, "tcodes": item.tcodes}

    @app.post("/sod/user-roles")
    def upsert_user_roles(item: UserRolesIn, tenant_id: str = Depends(_tenant)):
        with _LOCK:
            _USER_ROLES[(tenant_id, item.sap_user)] = sorted(set(item.roles))
        return {"tenant_id": tenant_id, "sap_user": item.sap_user, "roles": item.roles}

    @app.post("/sod/recompute")
    def recompute(tenant_id: str = Depends(_tenant)):
        role_map = {
            role: tcodes
            for (tid, role), tcodes in _ROLE_MAP.items()
            if tid == tenant_id
        }
        users = {
            user: roles
            for (tid, user), roles in _USER_ROLES.items()
            if tid == tenant_id
        }
        if not users:
            raise HTTPException(404, "No users registered for this tenant — POST /sod/user-roles first")

        found: list[Violation] = []
        for sap_user, roles in users.items():
            found.extend(
                evaluate_user(
                    tenant_id=tenant_id,
                    sap_user=sap_user,
                    roles=roles,
                    role_tcode_map=role_map,
                    risks=_RISKS,
                )
            )

        with _LOCK:
            _VIOLATIONS[tenant_id] = found

        return {
            "tenant_id": tenant_id,
            "users_evaluated": len(users),
            "violations_found": len(found),
            "by_severity": _counts(found),
        }

    @app.get("/sod/violations")
    def list_violations(
        user: str | None = None,
        risk: str | None = None,
        severity: str | None = None,
        tenant_id: str = Depends(_tenant),
    ):
        items = list(_VIOLATIONS.get(tenant_id, []))
        if user:
            items = [v for v in items if v.sap_user == user]
        if risk:
            items = [v for v in items if v.risk_id == risk]
        if severity:
            items = [v for v in items if v.severity == severity]
        return {"tenant_id": tenant_id, "count": len(items), "violations": [asdict(v) for v in items]}

    @app.get("/sod/user/{sap_user}/graph")
    def user_graph(sap_user: str, tenant_id: str = Depends(_tenant)):
        roles = _USER_ROLES.get((tenant_id, sap_user), [])
        edges = [
            {"role": r, "tcode": tc}
            for r in roles
            for tc in _ROLE_MAP.get((tenant_id, r), [])
        ]
        viols = [asdict(v) for v in _VIOLATIONS.get(tenant_id, []) if v.sap_user == sap_user]
        return {
            "tenant_id": tenant_id,
            "sap_user": sap_user,
            "roles": roles,
            "edges": edges,
            "violations": viols,
        }

    return app


def _counts(vs: list[Violation]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for v in vs:
        out[v.severity] += 1
    return dict(out)


app = create_app()

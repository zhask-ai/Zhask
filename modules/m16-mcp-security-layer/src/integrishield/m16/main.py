"""
M16 — MCP Security Layer.

Sits between Claude (via MCP protocol) and IntegriShield's internal
modules. Enforces RBAC policy on every tool call that Claude makes —
before any module executes it.

Dev-4 scope:
  - Role-based ALLOW / DENY / MODIFY decisions via built-in ruleset
  - Prompt-injection heuristics on free-text tool arguments
  - Row-cap rewrites for bulk-read tools (rfc_read_table)
  - Rolling audit log of the last 500 decisions
  - Dashboard-facing stats + decision history endpoints

Deferred to Dev-5:
  - Full JWT / OIDC caller identification (replaces trusted role header)
  - Persistent audit log in Postgres
  - Per-tenant rate limiting
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.telemetry import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("M16 MCP Security Layer starting", extra={"svc": "m16"})
    yield
    logger.info("M16 shutting down", extra={"svc": "m16"})


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M16 MCP Security Layer",
        description=(
            "Policy enforcement layer between Claude and IntegriShield MCP "
            "modules. RBAC ruleset + prompt-injection heuristics + rolling "
            "audit log."
        ),
        version="0.4.0",
        lifespan=lifespan,
    )

    from integrishield.m16.routes.health import router as health_router
    from integrishield.m16.routes.policy import router as policy_router

    app.include_router(health_router)
    app.include_router(policy_router, prefix="/policy")

    return app


app = create_app()

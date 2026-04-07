"""
M16 — MCP Security Layer  [POC STUB]
======================================
Sits between Claude (via MCP protocol) and IntegriShield's internal modules.
Enforces security policy on every tool call that Claude makes — before any
module executes it.

POC status: STUB — health + policy endpoints only.
            Full build scheduled post-funding.

Full build will include:
  - MCP request interceptor: validates tool-call inputs against policy rules
  - Rate limiting per Claude session / user identity
  - Tool-call audit log (who called what, when, with what args)
  - Prompt injection detection on free-text tool arguments
  - Allowlist of permitted MCP tools per role (SOC analyst vs. admin)
  - Deny-list for high-risk tools (e.g. bulk data export without approval)
  - Integration with M12 (Rules Engine, Dev 4) for policy evaluation

Why this matters for SAP security:
  Dev 3's M05 (SAP MCP Suite) exposes 17 SAP tools to Claude.
  Without M16, any Claude session could call RFC_READ_TABLE with no
  row limit and exfiltrate the entire vendor master.  M16 intercepts
  that call, checks the requesting user's role, applies row caps,
  and logs the access — before it reaches M05.

Event flow (post-build):
  Claude tool call
    → M16 intercept
        → policy check (allow / deny / modify)
            → M05 / other MCP module (if allowed)
                → response back through M16 (audit log written)
                    → Claude

Owned by Dev 1.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.telemetry import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("M16 MCP Security Layer starting (POC stub)", extra={"svc": "m16"})
    yield
    logger.info("M16 shutting down", extra={"svc": "m16"})


def create_app() -> FastAPI:
    app = FastAPI(
        title="IntegriShield — M16 MCP Security Layer",
        description=(
            "**POC STUB** — Policy enforcement layer between Claude and "
            "IntegriShield MCP modules. Full implementation post-funding."
        ),
        version="0.0.1-stub",
        lifespan=lifespan,
    )

    from integrishield.m16.routes.health import router as health_router
    from integrishield.m16.routes.policy import router as policy_router

    app.include_router(health_router)
    app.include_router(policy_router, prefix="/policy")

    return app


app = create_app()

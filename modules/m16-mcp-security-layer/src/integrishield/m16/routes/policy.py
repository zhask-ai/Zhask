"""
M16 — Policy routes.

Real RBAC policy enforcement for MCP tool calls. Called by any module
(m05 SAP MCP Suite, etc.) before it executes a Claude-initiated tool
invocation.

Endpoints:
  POST /policy/evaluate    — decide ALLOW / DENY / MODIFY for a call
  GET  /policy/rules       — list active ruleset
  GET  /policy/decisions   — rolling audit log of recent decisions
  GET  /policy/stats       — aggregate counters for the dashboard
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from integrishield.m16.services.policy_engine import ENGINE

router = APIRouter(tags=["policy"])


class PolicyEvaluateRequest(BaseModel):
    session_id: str
    user_id: str
    role: str = Field(
        default="SOC_ANALYST",
        description="Caller's RBAC role — SOC_ADMIN, SOC_ANALYST, AUDITOR, SERVICE.",
    )
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    source_module: str = "unknown"


class PolicyEvaluateResponse(BaseModel):
    decision: Literal["ALLOW", "DENY", "MODIFY"]
    modified_args: dict[str, Any] | None = None
    reason: str
    rule_id: str
    audit_id: str
    timestamp: str


class PolicyRule(BaseModel):
    rule_id: str
    description: str
    roles: list[str]
    tool_pattern: str
    action: Literal["ALLOW", "DENY", "MODIFY"]
    modifier: dict[str, Any] = Field(default_factory=dict)


class PolicyRulesResponse(BaseModel):
    rules: list[PolicyRule]
    default_action: Literal["ALLOW", "DENY", "MODIFY"] = "DENY"
    note: str


class PolicyDecision(BaseModel):
    audit_id: str
    timestamp: str
    decision: Literal["ALLOW", "DENY", "MODIFY"]
    rule_id: str
    reason: str
    session_id: str
    user_id: str
    role: str
    tool_name: str
    source_module: str
    modified_args: dict[str, Any] | None = None


class PolicyDecisionsResponse(BaseModel):
    decisions: list[PolicyDecision]
    counters: dict[str, int]


@router.post("/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate(body: PolicyEvaluateRequest) -> PolicyEvaluateResponse:
    entry = ENGINE.evaluate(
        session_id=body.session_id,
        user_id=body.user_id,
        role=body.role,
        tool_name=body.tool_name,
        tool_args=body.tool_args,
        source_module=body.source_module,
    )
    return PolicyEvaluateResponse(
        decision=entry["decision"],
        modified_args=entry["modified_args"],
        reason=entry["reason"],
        rule_id=entry["rule_id"],
        audit_id=entry["audit_id"],
        timestamp=entry["timestamp"],
    )


@router.get("/rules", response_model=PolicyRulesResponse)
async def get_rules() -> PolicyRulesResponse:
    return PolicyRulesResponse(
        rules=[PolicyRule(**r) for r in ENGINE.rules_snapshot()],
        default_action="DENY",
        note="Top-down first-match ruleset. Unmatched requests are denied.",
    )


@router.get("/decisions", response_model=PolicyDecisionsResponse)
async def get_decisions(
    limit: int = Query(default=100, ge=1, le=500),
) -> PolicyDecisionsResponse:
    decisions = [PolicyDecision(**d) for d in ENGINE.recent_decisions(limit=limit)]
    return PolicyDecisionsResponse(
        decisions=decisions,
        counters=ENGINE.counters(),
    )


@router.get("/stats")
async def get_stats() -> dict[str, Any]:
    return {
        "counters": ENGINE.counters(),
        "rule_count": len(ENGINE.rules_snapshot()),
    }

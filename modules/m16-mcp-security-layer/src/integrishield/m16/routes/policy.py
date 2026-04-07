"""
M16 — Policy routes  [POC STUB]

POST /policy/evaluate  → stub: always returns ALLOW with a note.
GET  /policy/rules     → stub: returns empty ruleset.

The contract here is what Dev 3 (M05 SAP MCP Suite) will code against
when M16 gets its full implementation.  Keeping the shape stable now
means Dev 3 can build optimistically against this interface.
"""

from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["policy"])


class PolicyEvaluateRequest(BaseModel):
    """
    Sent by an MCP module before executing a tool call.
    M16 decides whether to allow, deny, or modify the call.
    """
    session_id:  str                   # Claude session / conversation ID
    user_id:     str                   # SAP or IdP user identity
    tool_name:   str                   # MCP tool being called, e.g. "rfc_read_table"
    tool_args:   dict[str, Any] = {}   # raw arguments from Claude
    source_module: str = "unknown"     # which MCP module is asking (m05, m07, …)


class PolicyEvaluateResponse(BaseModel):
    decision:     Literal["ALLOW", "DENY", "MODIFY"]
    modified_args: dict[str, Any] | None = None   # populated when decision=MODIFY
    reason:       str
    audit_id:     str | None = None


class PolicyRule(BaseModel):
    rule_id:     str
    description: str
    tool_pattern: str
    action:      Literal["ALLOW", "DENY", "MODIFY"]


class PolicyRulesResponse(BaseModel):
    rules: list[PolicyRule]
    note:  str


@router.post("/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate(body: PolicyEvaluateRequest) -> PolicyEvaluateResponse:
    """
    [STUB] Evaluate whether a Claude tool call should be allowed.

    Full M16 will:
      - Check user role against tool allowlist
      - Apply row-cap modifications for bulk-read tools
      - Detect prompt injection in free-text args
      - Write audit record to Postgres
      - Return DENY for high-risk tools without explicit approval
    """
    return PolicyEvaluateResponse(
        decision="ALLOW",
        modified_args=None,
        reason="POC stub — all calls allowed. Real policy enforcement post-funding.",
        audit_id=None,
    )


@router.get("/rules", response_model=PolicyRulesResponse)
async def get_rules() -> PolicyRulesResponse:
    """[STUB] Return the active policy ruleset."""
    return PolicyRulesResponse(
        rules=[],
        note="POC stub — no rules loaded yet",
    )

"""
M16 — Built-in RBAC ruleset.

Each rule is evaluated top-to-bottom against an incoming
PolicyEvaluateRequest. First match wins. If no rule matches, the
engine's default policy (DENY) is applied.

Tool patterns support a trailing `*` for prefix matching
(e.g. `rfc_*` matches `rfc_read_table`, `rfc_call_function`).

Roles in use:
  - SOC_ADMIN    : platform operators, can do anything
  - SOC_ANALYST  : day-to-day investigators, bulk reads get row-capped
  - AUDITOR      : read-only compliance personas
  - SERVICE      : machine-to-machine callers (webhooks, schedulers)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Decision = Literal["ALLOW", "DENY", "MODIFY"]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    roles: tuple[str, ...]
    tool_pattern: str
    action: Decision
    modifier: dict[str, Any] = field(default_factory=dict)


# Row cap applied to bulk-read tools for non-admin roles.
DEFAULT_ROW_CAP = 1000
AUDITOR_ROW_CAP = 500


RULESET: tuple[Rule, ...] = (
    Rule(
        rule_id="R-001",
        description="SOC admins can invoke any MCP tool without restriction.",
        roles=("SOC_ADMIN",),
        tool_pattern="*",
        action="ALLOW",
    ),
    Rule(
        rule_id="R-010",
        description="Auditors may read metadata and compliance tools only.",
        roles=("AUDITOR",),
        tool_pattern="get_*",
        action="ALLOW",
    ),
    Rule(
        rule_id="R-011",
        description="Auditors invoking table reads are row-capped to 500.",
        roles=("AUDITOR",),
        tool_pattern="rfc_read_table",
        action="MODIFY",
        modifier={"max_rows": AUDITOR_ROW_CAP},
    ),
    Rule(
        rule_id="R-012",
        description="Auditors cannot call any write or execute tool.",
        roles=("AUDITOR",),
        tool_pattern="rfc_call_function",
        action="DENY",
    ),
    Rule(
        rule_id="R-020",
        description="Analysts reading SAP tables are row-capped to 1000.",
        roles=("SOC_ANALYST",),
        tool_pattern="rfc_read_table",
        action="MODIFY",
        modifier={"max_rows": DEFAULT_ROW_CAP},
    ),
    Rule(
        rule_id="R-021",
        description="Analysts may query user, role, and authorization metadata.",
        roles=("SOC_ANALYST",),
        tool_pattern="get_*",
        action="ALLOW",
    ),
    Rule(
        rule_id="R-022",
        description="Analysts may run incident and compliance lookups.",
        roles=("SOC_ANALYST",),
        tool_pattern="list_*",
        action="ALLOW",
    ),
    Rule(
        rule_id="R-023",
        description="Analysts cannot invoke privileged RFC functions directly.",
        roles=("SOC_ANALYST",),
        tool_pattern="rfc_call_function",
        action="DENY",
    ),
    Rule(
        rule_id="R-030",
        description="Service accounts may publish webhook and evidence events.",
        roles=("SERVICE",),
        tool_pattern="publish_*",
        action="ALLOW",
    ),
    Rule(
        rule_id="R-031",
        description="Service accounts may not read SAP tables.",
        roles=("SERVICE",),
        tool_pattern="rfc_*",
        action="DENY",
    ),
)


# --- Prompt-injection heuristics ----------------------------------------

INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "disregard the above",
    "system:",
    "</system>",
    "<|im_start|>",
    "you are now",
    "act as",
    "jailbreak",
)

# Large opaque blobs in args are suspicious.
MAX_ARG_STRING_LEN = 2048


def pattern_matches(pattern: str, tool_name: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return tool_name.startswith(pattern[:-1])
    return pattern == tool_name

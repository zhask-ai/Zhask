"""
M16 — Policy engine.

Evaluates an MCP tool call against the built-in RBAC ruleset and a set
of prompt-injection heuristics. Keeps a rolling in-memory audit log of
the last 500 decisions so operators (and the dashboard) can inspect
recent activity.
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque

from integrishield.m16.services.rules_config import (
    INJECTION_MARKERS,
    MAX_ARG_STRING_LEN,
    RULESET,
    Decision,
    Rule,
    pattern_matches,
)

_AUDIT_MAX = 500


class PolicyEngine:
    """Stateless rule matcher + rolling audit buffer."""

    def __init__(self) -> None:
        self._audit: Deque[dict[str, Any]] = deque(maxlen=_AUDIT_MAX)
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "total": 0,
            "ALLOW": 0,
            "DENY": 0,
            "MODIFY": 0,
        }

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def evaluate(
        self,
        *,
        session_id: str,
        user_id: str,
        role: str,
        tool_name: str,
        tool_args: dict[str, Any],
        source_module: str,
    ) -> dict[str, Any]:
        injection_hit = self._scan_injection(tool_args)
        if injection_hit is not None:
            return self._record(
                decision="DENY",
                reason=f"Prompt-injection heuristic matched: {injection_hit}",
                rule_id="R-INJ",
                modified_args=None,
                session_id=session_id,
                user_id=user_id,
                role=role,
                tool_name=tool_name,
                source_module=source_module,
            )

        rule = self._match_rule(role=role, tool_name=tool_name)
        if rule is None:
            return self._record(
                decision="DENY",
                reason=(
                    f"No policy rule permits role='{role}' to invoke "
                    f"tool='{tool_name}'. Default-deny applied."
                ),
                rule_id="R-DEFAULT",
                modified_args=None,
                session_id=session_id,
                user_id=user_id,
                role=role,
                tool_name=tool_name,
                source_module=source_module,
            )

        modified_args: dict[str, Any] | None = None
        if rule.action == "MODIFY":
            modified_args = dict(tool_args)
            modified_args.update(rule.modifier)

        return self._record(
            decision=rule.action,
            reason=rule.description,
            rule_id=rule.rule_id,
            modified_args=modified_args,
            session_id=session_id,
            user_id=user_id,
            role=role,
            tool_name=tool_name,
            source_module=source_module,
        )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def recent_decisions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._audit)
        return list(reversed(items))[:limit]

    def counters(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    @staticmethod
    def rules_snapshot() -> list[dict[str, Any]]:
        return [
            {
                "rule_id": r.rule_id,
                "description": r.description,
                "roles": list(r.roles),
                "tool_pattern": r.tool_pattern,
                "action": r.action,
                "modifier": r.modifier,
            }
            for r in RULESET
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _match_rule(self, *, role: str, tool_name: str) -> Rule | None:
        for rule in RULESET:
            if role in rule.roles and pattern_matches(rule.tool_pattern, tool_name):
                return rule
        return None

    @staticmethod
    def _scan_injection(tool_args: dict[str, Any]) -> str | None:
        for value in tool_args.values():
            if not isinstance(value, str):
                continue
            lower = value.lower()
            for marker in INJECTION_MARKERS:
                if marker in lower:
                    return marker
            if len(value) > MAX_ARG_STRING_LEN:
                return f"arg length {len(value)} exceeds {MAX_ARG_STRING_LEN}"
        return None

    def _record(
        self,
        *,
        decision: Decision,
        reason: str,
        rule_id: str,
        modified_args: dict[str, Any] | None,
        session_id: str,
        user_id: str,
        role: str,
        tool_name: str,
        source_module: str,
    ) -> dict[str, Any]:
        audit_id = str(uuid.uuid4())
        entry = {
            "audit_id": audit_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": decision,
            "rule_id": rule_id,
            "reason": reason,
            "session_id": session_id,
            "user_id": user_id,
            "role": role,
            "tool_name": tool_name,
            "source_module": source_module,
            "modified_args": modified_args,
        }
        with self._lock:
            self._audit.append(entry)
            self._counters["total"] += 1
            self._counters[decision] = self._counters.get(decision, 0) + 1
        return entry


ENGINE = PolicyEngine()

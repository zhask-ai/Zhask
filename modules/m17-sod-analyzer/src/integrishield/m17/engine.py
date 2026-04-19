"""SoD violation evaluation engine."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

_SEED = Path(__file__).resolve().parents[3] / "config" / "risks_seed.json"


@dataclass(frozen=True)
class Risk:
    risk_id: str
    title: str
    severity: str
    description: str
    conflicting_tcodes: list[list[str]]
    control_ref: str = ""


@dataclass
class Violation:
    violation_id: str
    tenant_id: str
    sap_user: str
    risk_id: str
    risk_title: str
    severity: str
    conflicting_tcodes: list[str]
    roles_involved: list[str]
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def load_risks(path: Path = _SEED) -> list[Risk]:
    data = json.loads(path.read_text())
    return [
        Risk(
            risk_id=r["risk_id"],
            title=r["title"],
            severity=r["severity"],
            description=r.get("description", ""),
            conflicting_tcodes=r["conflicting_tcodes"],
            control_ref=r.get("control_ref", ""),
        )
        for r in data
    ]


def evaluate_user(
    *,
    tenant_id: str,
    sap_user: str,
    roles: list[str],
    role_tcode_map: dict[str, list[str]],
    risks: Iterable[Risk],
) -> list[Violation]:
    user_tcodes: dict[str, list[str]] = {}
    for role in roles:
        for tc in role_tcode_map.get(role, []):
            user_tcodes.setdefault(tc, []).append(role)

    violations: list[Violation] = []
    for risk in risks:
        sides_hit: list[tuple[str, list[str]]] = []
        for side in risk.conflicting_tcodes:
            matched = [tc for tc in side if tc in user_tcodes]
            if matched:
                sides_hit.append((matched[0], user_tcodes[matched[0]]))
        if len(sides_hit) >= 2:
            conflicting = [tc for tc, _ in sides_hit]
            roles_involved = sorted({r for _, rs in sides_hit for r in rs})
            violations.append(
                Violation(
                    violation_id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    sap_user=sap_user,
                    risk_id=risk.risk_id,
                    risk_title=risk.title,
                    severity=risk.severity,
                    conflicting_tcodes=conflicting,
                    roles_involved=roles_involved,
                )
            )
    return violations

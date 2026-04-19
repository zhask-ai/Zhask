"""Tenant-aware Redis stream naming.

Enforces the contract `integrishield:{tenant}:{family}` so modules cannot
accidentally read another tenant's events.
"""

from __future__ import annotations

from shared.auth.tenant import validate_tenant_id

_PREFIX = "integrishield"


def stream_name(tenant_id: str, family: str) -> str:
    tenant_id = validate_tenant_id(tenant_id)
    if not family or ":" in family or " " in family:
        raise ValueError(f"Invalid stream family '{family}'")
    return f"{_PREFIX}:{tenant_id}:{family}"


def parse_stream_name(name: str) -> tuple[str, str]:
    parts = name.split(":")
    if len(parts) != 3 or parts[0] != _PREFIX:
        raise ValueError(f"Stream name '{name}' does not match expected format")
    return parts[1], parts[2]


def tenant_pattern(tenant_id: str) -> str:
    tenant_id = validate_tenant_id(tenant_id)
    return f"{_PREFIX}:{tenant_id}:*"

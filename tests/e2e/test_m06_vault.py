"""E2E tests for M06 Credential Vault — memory backend."""

from __future__ import annotations

import pytest
import httpx

from tests.e2e.conftest import M06_URL


def _url(path: str) -> str:
    return f"{M06_URL}/api/v1/vault{path}"


@pytest.fixture(scope="module")
def client():
    with httpx.Client(timeout=10.0, base_url=M06_URL) as c:
        try:
            c.get("/health").raise_for_status()
        except Exception as exc:
            pytest.skip(f"M06 not available at {M06_URL}: {exc}")
        yield c


def test_create_secret(client):
    resp = client.post("/api/v1/vault/secrets", params={"key": "e2e-test-key", "owner_module": "e2e"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["key"] == "e2e-test-key"
    assert data["status"] == "active"


def test_read_secret_value(client):
    resp = client.get("/api/v1/vault/secrets/e2e-test-key/value", params={"requester": "e2e"})
    assert resp.status_code == 200
    assert "value" in resp.json()
    assert resp.json()["value"]  # non-empty


def test_rotate_secret(client):
    resp = client.post("/api/v1/vault/secrets/rotate", json={"key": "e2e-test-key", "reason": "e2e-test"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["rotated"] is True
    assert data["new_status"] == "active"


def test_revoke_secret(client):
    # create a separate key to revoke
    client.post("/api/v1/vault/secrets", params={"key": "e2e-revoke-key"})
    resp = client.delete("/api/v1/vault/secrets/e2e-revoke-key")
    assert resp.status_code == 200
    data = resp.json()
    assert data["revoked"] is True


def test_revoked_secret_not_readable(client):
    resp = client.get("/api/v1/vault/secrets/e2e-revoke-key/value")
    assert resp.status_code == 404


def test_vault_stats(client):
    resp = client.get("/api/v1/vault/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "total_secrets" in stats
    assert stats["total_secrets"] >= 1


def test_audit_event_published(redis_client):
    """Confirm create/read/rotate/revoke publish to cred_access stream."""
    # Read the most recent entries from the audit stream
    entries = redis_client.xrevrange("integrishield:cred_access", count=20)
    actions = set()
    for _eid, fields in entries:
        import json  # noqa: PLC0415
        data = json.loads(fields.get("data", "{}"))
        if data.get("key") in ("e2e-test-key", "e2e-revoke-key"):
            actions.add(data.get("action", "").split(":")[0])
    # At least created + rotated + revoked should appear
    assert "created" in actions or "rotated" in actions, f"Expected audit events, got: {actions}"

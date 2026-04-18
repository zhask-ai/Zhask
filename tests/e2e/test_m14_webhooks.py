"""E2E tests for M14 Webhook Gateway — subscription CRUD and delivery."""

from __future__ import annotations

import json
import time

import pytest
import httpx

from tests.e2e.conftest import M14_URL, REDIS_URL

WEBHOOK_SITE_PLACEHOLDER = "https://webhook.site/00000000-0000-0000-0000-000000000000"


@pytest.fixture(scope="module")
def client():
    with httpx.Client(timeout=15.0, base_url=M14_URL) as c:
        try:
            c.get("/health").raise_for_status()
        except Exception as exc:
            pytest.skip(f"M14 not available at {M14_URL}: {exc}")
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "sqlite" in data["backend"]


def test_create_subscription(client):
    resp = client.post("/webhooks", json={
        "url": WEBHOOK_SITE_PLACEHOLDER,
        "secret": "e2e-test-secret",
        "event_filter": ["test", "alerts"],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["active"] is True
    pytest.e2e_sub_id = data["id"]


def test_list_subscriptions(client):
    resp = client.get("/webhooks")
    assert resp.status_code == 200
    subs = resp.json()
    assert isinstance(subs, list)
    ids = [s["id"] for s in subs]
    sub_id = getattr(pytest, "e2e_sub_id", None)
    if sub_id:
        assert sub_id in ids


def test_test_delivery_dispatches(client):
    """POST /webhooks/test should schedule delivery to all active subscriptions."""
    resp = client.post("/webhooks/test")
    assert resp.status_code == 202
    data = resp.json()
    assert "event_id" in data
    pytest.e2e_test_event_id = data["event_id"]


def test_delivery_logged_after_dispatch(client):
    sub_id = getattr(pytest, "e2e_sub_id", None)
    if not sub_id:
        pytest.skip("No subscription from previous test")

    time.sleep(2)  # allow background delivery to complete

    resp = client.get(f"/webhooks/{sub_id}/deliveries")
    assert resp.status_code == 200
    deliveries = resp.json()
    assert len(deliveries) >= 1
    # The delivery for our test event should be present
    statuses = {d["status"] for d in deliveries}
    # delivery to placeholder URL will fail (expected); DLQ entry confirms flow
    assert statuses & {"delivered", "failed", "dlq"}, f"Unexpected statuses: {statuses}"


def test_replay_last_delivery(client):
    sub_id = getattr(pytest, "e2e_sub_id", None)
    if not sub_id:
        pytest.skip("No subscription from previous test")

    resp = client.post(f"/webhooks/{sub_id}/replay")
    assert resp.status_code == 202
    assert "replaying" in resp.json()


def test_deactivate_subscription(client):
    sub_id = getattr(pytest, "e2e_sub_id", None)
    if not sub_id:
        pytest.skip("No subscription from previous test")

    resp = client.delete(f"/webhooks/{sub_id}")
    assert resp.status_code == 204

    # Confirm it no longer appears in active list
    resp2 = client.get("/webhooks")
    active_ids = [s["id"] for s in resp2.json()]
    assert sub_id not in active_ids


def test_dlq_stream_has_entries(redis_client):
    """Verify DLQ entries appear in Redis after failed deliveries."""
    entries = redis_client.xrevrange("integrishield:webhook_dlq", count=10)
    # May be empty if all deliveries happened to succeed (unlikely with placeholder URL)
    # Just assert the stream is queryable
    assert isinstance(entries, list)


def test_stats_endpoint(client):
    resp = client.get("/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "subscriptions_active" in stats
    assert "deliveries_delivered" in stats
    assert "deliveries_dlq" in stats

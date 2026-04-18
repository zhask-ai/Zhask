"""E2E tests for M13 SBOM Scanner — live CVE feeds and cache."""

from __future__ import annotations

import base64
import time

import pytest
import httpx

from tests.e2e.conftest import M13_URL

# Minimal ABAP snippet using a third-party function module known to appear in NVD SAP advisories
_ABAP_SNIPPET = """
REPORT z_test_sbom.

* Include a known third-party component
INCLUDE zfin_utils.

* Call a function module in a partner namespace
CALL FUNCTION '/PARTNER/UTIL_RFC_PROXY'
  EXPORTING
    iv_input = 'test'.
"""


def _url(path: str) -> str:
    return f"{M13_URL}{path}"


@pytest.fixture(scope="module")
def client():
    with httpx.Client(timeout=30.0, base_url=M13_URL) as c:
        try:
            c.get("/health").raise_for_status()
        except Exception as exc:
            pytest.skip(f"M13 not available at {M13_URL}: {exc}")
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_scan_returns_scan_id(client):
    payload = {
        "filename": "z_test.abap",
        "content": base64.b64encode(_ABAP_SNIPPET.encode()).decode(),
        "encoding": "base64",
        "tenant_id": "e2e",
    }
    resp = client.post("/api/v1/sbom/scans", json=payload)
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    pytest.e2e_scan_id = data["scan_id"]


def test_scan_completes(client):
    scan_id = getattr(pytest, "e2e_scan_id", None)
    if not scan_id:
        pytest.skip("No scan_id from previous test")

    for _ in range(15):
        resp = client.get(f"/api/v1/sbom/scans/{scan_id}")
        assert resp.status_code == 200
        if resp.json()["status"] in ("complete", "failed"):
            break
        time.sleep(1)

    data = resp.json()
    assert data["status"] == "complete", f"Scan failed or timed out: {data}"


def test_scan_has_components(client):
    scan_id = getattr(pytest, "e2e_scan_id", None)
    if not scan_id:
        pytest.skip("No scan_id from previous test")

    resp = client.get(f"/api/v1/sbom/scans/{scan_id}")
    data = resp.json()
    assert len(data.get("components", [])) > 0, "Expected at least one component extracted"


def test_cve_cache_stats(client):
    resp = client.get("/api/v1/cve/cache/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "total_entries" in stats
    assert "components_cached" in stats


def test_cve_refresh_endpoint(client):
    resp = client.post(
        "/api/v1/cve/refresh",
        json=["ZFIN_UTILS", "/PARTNER/UTIL_RFC_PROXY"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] in ("refresh_scheduled", "full_invalidation")


def test_sbom_export(client):
    scan_id = getattr(pytest, "e2e_scan_id", None)
    if not scan_id:
        pytest.skip("No scan_id from previous test")

    resp = client.get(f"/api/v1/sbom/scans/{scan_id}/sbom")
    assert resp.status_code == 200
    sbom = resp.json()
    assert sbom.get("bomFormat") == "CycloneDX"
    assert sbom.get("specVersion") == "1.4"

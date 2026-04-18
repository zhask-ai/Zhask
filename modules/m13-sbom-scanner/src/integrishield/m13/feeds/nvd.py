"""NVD 2.0 API client for M13 SBOM Scanner.

Rate limits (unauthenticated): 5 requests / 30 s.
Set M13_NVD_API_KEY to lift the limit to 50 requests / 30 s.

API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_RESULTS = 20
_REQUEST_DELAY = 6.5  # seconds between requests without API key (safe under 5/30s)
_REQUEST_DELAY_KEYED = 0.65  # seconds with API key


class NVDFeed:
    """Synchronous NVD 2.0 client — uses httpx.Client under the hood."""

    def __init__(self, api_key: str = "", search_prefix: str = "SAP") -> None:
        try:
            import httpx  # noqa: PLC0415

            self._httpx = httpx
        except ImportError as exc:
            raise RuntimeError("httpx required for NVDFeed — pip install httpx") from exc

        self._api_key = api_key
        self._search_prefix = search_prefix
        self._last_request: float = 0.0
        self._delay = _REQUEST_DELAY_KEYED if api_key else _REQUEST_DELAY

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_request = time.monotonic()

    def lookup(self, component: str) -> list[dict[str, Any]]:
        """Search NVD for CVEs matching the component name. Returns CVE dicts."""
        keyword = f"{self._search_prefix} {component}" if self._search_prefix else component
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        self._throttle()
        try:
            with self._httpx.Client(timeout=15.0) as client:
                resp = client.get(
                    _NVD_BASE,
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": _MAX_RESULTS,
                    },
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("NVD lookup failed for '%s': %s", component, exc)
            return []

        return self._parse(data)

    @staticmethod
    def _parse(data: dict[str, Any]) -> list[dict[str, Any]]:
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Extract best CVSS score (prefer v3.1 > v3.0 > v2)
            cvss = 0.0
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss = float(
                        entries[0].get("cvssData", {}).get("baseScore", 0.0)
                    )
                    break

            # Extract English description
            summary = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    summary = desc.get("value", "")
                    break

            results.append({"cve_id": cve_id, "cvss": cvss, "summary": summary, "source": "nvd"})
        return results

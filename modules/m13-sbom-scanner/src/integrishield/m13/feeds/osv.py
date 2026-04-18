"""OSV.dev API client for M13 SBOM Scanner — secondary CVE cross-check.

API docs: https://google.github.io/osv.dev/post-v1-query/
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OSVFeed:
    """Synchronous OSV.dev client.

    Queries by package name in a configurable ecosystem (default: PyPI for demo;
    set ecosystem="" to use the general keyword search).
    """

    def __init__(self, ecosystem: str = "") -> None:
        try:
            import httpx  # noqa: PLC0415

            self._httpx = httpx
        except ImportError as exc:
            raise RuntimeError("httpx required for OSVFeed — pip install httpx") from exc

        self._ecosystem = ecosystem

    def lookup(self, component: str) -> list[dict[str, Any]]:
        """Query OSV for vulnerabilities matching the component."""
        if self._ecosystem:
            body: dict[str, Any] = {
                "package": {"name": component, "ecosystem": self._ecosystem}
            }
        else:
            # fallback: full-text query
            body = {"query": component}

        try:
            with self._httpx.Client(timeout=10.0) as client:
                resp = client.post(_OSV_QUERY_URL, json=body)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("OSV lookup failed for '%s': %s", component, exc)
            return []

        return self._parse(data)

    @staticmethod
    def _parse(data: dict[str, Any]) -> list[dict[str, Any]]:
        results = []
        for vuln in data.get("vulns", []):
            osv_id = vuln.get("id", "")
            if not osv_id:
                continue

            # Map OSV aliases to CVE IDs if available
            cve_id = osv_id
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            summary = vuln.get("summary", vuln.get("details", ""))[:500]

            # OSV severity is in database_specific or severity array
            cvss = 0.0
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    # Parse CVSS vector to get base score (simplified: just note it)
                    cvss = 7.0  # conservative estimate without full vector parsing
                    break

            results.append({
                "cve_id": cve_id,
                "cvss": cvss,
                "summary": summary,
                "source": "osv",
            })
        return results

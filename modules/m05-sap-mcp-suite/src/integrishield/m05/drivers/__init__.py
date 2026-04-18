"""SAP data driver protocol and factory for M05 MCP Suite."""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class SAPDriver(Protocol):
    """Minimal contract all SAP data drivers must satisfy."""

    def read_table(self, table_name: str, max_rows: int) -> list[dict[str, Any]]: ...
    def driver_name(self) -> str: ...


def _fetch_vault_creds(key: str, m06_url: str, requester: str = "m05") -> dict[str, Any]:
    """
    Fetch JSON-encoded credentials from M06 Credential Vault.
    Returns empty dict on any error (callers fall back to env vars).
    """
    try:
        import httpx  # noqa: PLC0415

        url = f"{m06_url.rstrip('/')}/api/v1/vault/secrets/{key}/value"
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url, params={"requester": requester})
            resp.raise_for_status()
            raw_value = resp.json().get("value", "{}")
            return json.loads(raw_value) if isinstance(raw_value, str) else raw_value
    except Exception as exc:
        logger.warning("Could not fetch creds key='%s' from M06: %s", key, exc)
        return {}


def get_driver() -> SAPDriver:
    """Return the configured SAP driver based on M05_SAP_DRIVER env var."""
    from integrishield.m05.config import settings  # noqa: PLC0415

    driver_name = settings.sap_driver.lower()

    if driver_name == "rfc":
        from integrishield.m05.drivers.rfc import SAPRFCDriver  # noqa: PLC0415

        creds: dict[str, Any] = {}
        if settings.m06_url and settings.sap_rfc_cred_key:
            creds = _fetch_vault_creds(settings.sap_rfc_cred_key, settings.m06_url)
        return SAPRFCDriver(creds=creds)

    if driver_name == "sql":
        from integrishield.m05.drivers.sql import SAPSQLDriver  # noqa: PLC0415

        creds = {}
        if settings.m06_url and settings.sap_sql_cred_key:
            creds = _fetch_vault_creds(settings.sap_sql_cred_key, settings.m06_url)
        return SAPSQLDriver(creds=creds)

    from integrishield.m05.drivers.mock import MockDriver  # noqa: PLC0415

    return MockDriver()

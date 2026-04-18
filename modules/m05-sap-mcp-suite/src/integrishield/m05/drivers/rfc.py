"""SAP NetWeaver RFC driver for M05 MCP Suite (M05_SAP_DRIVER=rfc).

Requires pyrfc and the SAP NW RFC SDK C library.
Install: pip install pyrfc   (needs SAPNWRFC_HOME env var pointing to SDK)

Credentials are fetched from M06 Credential Vault at startup and expected
to be a JSON object with these keys:
  ashost, sysnr, client, user, passwd
  (optional: lang, trace, saprouter)

Fallback: if vault is unavailable, reads from env vars directly:
  SAP_RFC_ASHOST, SAP_RFC_SYSNR, SAP_RFC_CLIENT, SAP_RFC_USER, SAP_RFC_PASSWD
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_MAX_ROWS = 100


class SAPRFCDriver:
    """
    Calls RFC_READ_TABLE via pyrfc to read SAP tables.

    Connection is established lazily on first read_table() call and
    cached for the process lifetime. If the connection drops, it is
    re-established transparently.
    """

    def __init__(self, creds: dict[str, Any] | None = None) -> None:
        self._creds = self._resolve_creds(creds or {})
        self._conn = None

    @staticmethod
    def _resolve_creds(vault_creds: dict[str, Any]) -> dict[str, Any]:
        """Merge vault creds with env-var fallbacks."""
        return {
            "ashost": vault_creds.get("ashost") or os.getenv("SAP_RFC_ASHOST", ""),
            "sysnr":  vault_creds.get("sysnr")  or os.getenv("SAP_RFC_SYSNR", "00"),
            "client": vault_creds.get("client")  or os.getenv("SAP_RFC_CLIENT", "100"),
            "user":   vault_creds.get("user")    or os.getenv("SAP_RFC_USER", ""),
            "passwd": vault_creds.get("passwd")  or os.getenv("SAP_RFC_PASSWD", ""),
        }

    def driver_name(self) -> str:
        return "rfc"

    def _get_connection(self):
        if self._conn is not None:
            try:
                self._conn.ping()
                return self._conn
            except Exception:
                self._conn = None

        try:
            import pyrfc  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "pyrfc package required for SAPRFCDriver — "
                "install pyrfc and set SAPNWRFC_HOME"
            ) from exc

        if not self._creds.get("ashost"):
            raise RuntimeError(
                "SAP RFC host not configured. Set SAP_RFC_ASHOST or store credentials in M06."
            )

        self._conn = pyrfc.Connection(**{k: v for k, v in self._creds.items() if v})
        logger.info("SAPRFCDriver connected to %s client=%s", self._creds["ashost"], self._creds["client"])
        return self._conn

    def read_table(self, table_name: str, max_rows: int = _DEFAULT_MAX_ROWS) -> list[dict[str, Any]]:
        """
        Read up to max_rows rows from a SAP table via RFC_READ_TABLE.
        Returns a list of dicts with field names as keys.
        """
        conn = self._get_connection()
        result = conn.call(
            "RFC_READ_TABLE",
            QUERY_TABLE=table_name,
            ROWCOUNT=max_rows,
            DELIMITER="|",
        )

        # Parse field metadata
        fields = [f["FIELDNAME"] for f in result.get("FIELDS", [])]
        rows: list[dict[str, Any]] = []

        for entry in result.get("DATA", []):
            raw = entry.get("WA", "")
            values = [v.strip() for v in raw.split("|")]
            row = dict(zip(fields, values))
            row["_source"] = "rfc"
            rows.append(row)

        logger.debug("SAPRFCDriver read_table %s → %d rows", table_name, len(rows))
        return rows

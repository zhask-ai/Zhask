"""SAP HANA / generic SQL driver for M05 MCP Suite (M05_SAP_DRIVER=sql).

Supports two SQL backends selected by M05_SAP_SQL_DIALECT:
  "hana"    — SAP HANA via hdbcli   (pip install hdbcli)
  "generic" — Any DBAPI2 DSN string via pyodbc (pip install pyodbc)

Credentials JSON (from M06 vault or env fallback):
  host, port, user, password, database (optional for HANA)

Env var fallbacks:
  SAP_SQL_HOST, SAP_SQL_PORT, SAP_SQL_USER, SAP_SQL_PASSWORD, SAP_SQL_DATABASE
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class SAPSQLDriver:
    """
    Read-only SQL driver for SAP HANA or generic ODBC connections.
    Connection is established lazily and cached.
    """

    def __init__(self, creds: dict[str, Any] | None = None) -> None:
        self._creds = self._resolve_creds(creds or {})
        self._dialect = os.getenv("M05_SAP_SQL_DIALECT", "hana").lower()
        self._conn = None

    @staticmethod
    def _resolve_creds(vault_creds: dict[str, Any]) -> dict[str, Any]:
        return {
            "host":     vault_creds.get("host")     or os.getenv("SAP_SQL_HOST", ""),
            "port":     int(vault_creds.get("port") or os.getenv("SAP_SQL_PORT", "30015")),
            "user":     vault_creds.get("user")     or os.getenv("SAP_SQL_USER", ""),
            "password": vault_creds.get("password") or os.getenv("SAP_SQL_PASSWORD", ""),
            "database": vault_creds.get("database") or os.getenv("SAP_SQL_DATABASE", ""),
        }

    def driver_name(self) -> str:
        return f"sql:{self._dialect}"

    def _get_connection(self):
        if self._conn is not None:
            try:
                self._conn.cursor().execute("SELECT 1 FROM DUMMY")
                return self._conn
            except Exception:
                self._conn = None

        if not self._creds.get("host"):
            raise RuntimeError(
                "SAP SQL host not configured. Set SAP_SQL_HOST or store credentials in M06."
            )

        if self._dialect == "hana":
            try:
                from hdbcli import dbapi  # noqa: PLC0415
            except ImportError as exc:
                raise RuntimeError(
                    "hdbcli package required for SQL/HANA driver — pip install hdbcli"
                ) from exc

            self._conn = dbapi.connect(
                address=self._creds["host"],
                port=self._creds["port"],
                user=self._creds["user"],
                password=self._creds["password"],
            )
        else:
            try:
                import pyodbc  # noqa: PLC0415
            except ImportError as exc:
                raise RuntimeError(
                    "pyodbc package required for SQL/generic driver — pip install pyodbc"
                ) from exc

            dsn = (
                f"DRIVER={{ODBC Driver}};SERVER={self._creds['host']};"
                f"PORT={self._creds['port']};UID={self._creds['user']};"
                f"PWD={self._creds['password']}"
            )
            self._conn = pyodbc.connect(dsn, readonly=True)

        logger.info(
            "SAPSQLDriver connected (dialect=%s host=%s port=%s)",
            self._dialect, self._creds["host"], self._creds["port"],
        )
        return self._conn

    def read_table(self, table_name: str, max_rows: int = 100) -> list[dict[str, Any]]:
        """Execute a SELECT on the SAP table and return rows as dicts."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Read-only: plain SELECT with row limit; table_name sanitised to alphanum + /
        safe_table = "".join(c for c in table_name if c.isalnum() or c in ("_", "/"))
        cursor.execute(f"SELECT TOP {max_rows} * FROM {safe_table}")  # noqa: S608

        columns = [desc[0] for desc in cursor.description]
        rows = []
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            d["_source"] = self.driver_name()
            rows.append(d)

        logger.debug("SAPSQLDriver read_table %s → %d rows", table_name, len(rows))
        return rows

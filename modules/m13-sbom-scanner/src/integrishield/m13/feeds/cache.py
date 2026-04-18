"""SQLite-backed CVE cache with 24-hour TTL for M13 SBOM Scanner."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cve_cache (
    component   TEXT    NOT NULL,
    cve_id      TEXT    NOT NULL,
    cvss        REAL    NOT NULL DEFAULT 0.0,
    summary     TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT 'nvd',
    fetched_at  TEXT    NOT NULL,
    PRIMARY KEY (component, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_cache_component ON cve_cache (component);
"""


class CVECache:
    """Thread-safe SQLite cache. All public methods are synchronous."""

    def __init__(self, db_path: str, ttl_hours: int = 24) -> None:
        self._db_path = db_path
        self._ttl = timedelta(hours=ttl_hours)
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_CREATE_TABLE)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def get(self, component: str) -> list[dict[str, Any]] | None:
        """Return cached CVE list for component, or None if stale/missing."""
        cutoff = (datetime.now(timezone.utc) - self._ttl).isoformat()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_cache WHERE component = ? AND fetched_at >= ?",
                (component.upper(), cutoff),
            ).fetchall()
        if not rows:
            return None
        return [
            {
                "cve_id": r["cve_id"],
                "cvss": r["cvss"],
                "summary": r["summary"],
                "source": r["source"],
            }
            for r in rows
        ]

    def put(self, component: str, cves: list[dict[str, Any]], source: str = "nvd") -> None:
        """Store CVE list for component, replacing any existing entries."""
        now = datetime.now(timezone.utc).isoformat()
        comp_upper = component.upper()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM cve_cache WHERE component = ?", (comp_upper,))
            if cves:
                conn.executemany(
                    "INSERT OR REPLACE INTO cve_cache "
                    "(component, cve_id, cvss, summary, source, fetched_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            comp_upper,
                            c.get("cve_id", ""),
                            float(c.get("cvss", 0.0)),
                            c.get("summary", ""),
                            source,
                            now,
                        )
                        for c in cves
                        if c.get("cve_id")
                    ],
                )
            else:
                # Cache a negative result so we don't hammer NVD on every miss
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache "
                    "(component, cve_id, cvss, summary, source, fetched_at) "
                    "VALUES (?, '__none__', 0.0, '', ?, ?)",
                    (comp_upper, source, now),
                )

    def invalidate(self, component: str | None = None) -> int:
        """Delete cache entries for one component or all if component is None."""
        with self._lock, self._connect() as conn:
            if component:
                cur = conn.execute(
                    "DELETE FROM cve_cache WHERE component = ?", (component.upper(),)
                )
            else:
                cur = conn.execute("DELETE FROM cve_cache")
            return cur.rowcount

    def stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
            components = conn.execute(
                "SELECT COUNT(DISTINCT component) FROM cve_cache"
            ).fetchone()[0]
        return {"total_entries": total, "components_cached": components}

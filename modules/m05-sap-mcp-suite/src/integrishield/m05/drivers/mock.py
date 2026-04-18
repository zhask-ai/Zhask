"""Mock SAP driver — for demos and CI (M05_SAP_DRIVER=mock)."""

from __future__ import annotations

from typing import Any


class MockDriver:
    """Returns synthetic SAP table rows. Safe for CI and local dev."""

    def driver_name(self) -> str:
        return "mock"

    def read_table(self, table_name: str, max_rows: int) -> list[dict[str, Any]]:
        """Return plausible-looking mock rows for any table."""
        rows = []
        for i in range(min(max_rows, 10)):
            rows.append({
                "MANDT": "100",
                "TABLE": table_name,
                "KEY1": f"MOCK-{i:04d}",
                "CREATED": "2026-01-01",
                "DRIVER": "mock",
            })
        return rows

"""In-memory LRU scan result store."""

from __future__ import annotations

from collections import OrderedDict

from integrishield.m13.models import ScanResult


class ScanStore:
    """Thread-safe in-memory store for scan results with LRU eviction."""

    def __init__(self, max_size: int = 500) -> None:
        self._store: OrderedDict[str, ScanResult] = OrderedDict()
        self._max_size = max_size

    def put(self, result: ScanResult) -> None:
        """Store a scan result, evicting the oldest if at capacity."""
        if result.scan_id in self._store:
            self._store.move_to_end(result.scan_id)
        self._store[result.scan_id] = result
        if len(self._store) > self._max_size:
            self._store.popitem(last=False)

    def get(self, scan_id: str) -> ScanResult | None:
        return self._store.get(scan_id)

    def list(self, tenant_id: str = "", limit: int = 20) -> list[ScanResult]:
        results = list(self._store.values())
        results.reverse()  # newest first
        if tenant_id:
            results = [r for r in results if r.tenant_id == tenant_id]
        return results[:limit]

    def active_count(self) -> int:
        from integrishield.m13.models import ScanStatus

        return sum(
            1
            for r in self._store.values()
            if r.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
        )

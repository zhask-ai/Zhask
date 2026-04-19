"""In-memory ledger store (POC).

Swap with Postgres-backed implementation in production; the interface here
matches the columns in infrastructure/sql/migrations/003_ledger.sql.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from shared.audit.ledger import GENESIS_HASH, LedgerEntry, entry_hash, merkle_root


class LedgerStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, list[LedgerEntry]] = defaultdict(list)
        self._anchors: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def append(self, tenant_id: str, event_type: str, payload: dict[str, Any]) -> LedgerEntry:
        with self._lock:
            chain = self._entries[tenant_id]
            prev = chain[-1].hash if chain else GENESIS_HASH
            ts = datetime.now(timezone.utc).isoformat()
            h = entry_hash(prev, payload, ts)
            entry = LedgerEntry(
                seq=len(chain) + 1,
                tenant_id=tenant_id,
                event_type=event_type,
                payload=payload,
                timestamp=ts,
                prev_hash=prev,
                hash=h,
            )
            chain.append(entry)
            return entry

    def range(self, tenant_id: str, start: int = 1, end: int | None = None) -> list[LedgerEntry]:
        with self._lock:
            chain = list(self._entries[tenant_id])
        end = end or len(chain)
        return [e for e in chain if start <= e.seq <= end]

    def anchor(self, tenant_id: str) -> dict[str, Any]:
        with self._lock:
            chain = list(self._entries[tenant_id])
            if not chain:
                return {"tenant_id": tenant_id, "entry_count": 0, "merkle_root": GENESIS_HASH}
            leaves = [e.hash for e in chain]
            root = merkle_root(leaves)
            anchor = {
                "tenant_id": tenant_id,
                "window_start": chain[0].timestamp,
                "window_end": chain[-1].timestamp,
                "first_seq": chain[0].seq,
                "last_seq": chain[-1].seq,
                "entry_count": len(chain),
                "merkle_root": root,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._anchors[tenant_id].append(anchor)
            return anchor

    def anchors(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._anchors[tenant_id])


_store = LedgerStore()


def get_store() -> LedgerStore:
    return _store

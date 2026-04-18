"""In-memory vault backend — for tests and local dev (M06_VAULT_BACKEND=memory)."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any


class MemoryBackend:
    """Thread-safe in-memory secret store. Data is lost on restart."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def store(
        self, key: str, value: str, owner_module: str = "", tenant_id: str = ""
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        entry: dict[str, Any] = {
            "value": value,
            "status": "active",
            "created_at": now,
            "rotated_at": now,
            "owner_module": owner_module,
            "tenant_id": tenant_id,
        }
        with self._lock:
            self._store[key] = entry
        return entry

    def read(self, key: str) -> str | None:
        with self._lock:
            entry = self._store.get(key)
        if entry and entry.get("status") == "active":
            return entry["value"]
        return None

    def rotate(self, key: str, new_value: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            entry["value"] = new_value
            entry["rotated_at"] = datetime.now(timezone.utc)
            entry["status"] = "active"
            return dict(entry)

    def revoke(self, key: str) -> bool:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False
            entry["status"] = "revoked"
        return True

    def get_entry(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._store.get(key)
            return dict(entry) if entry is not None else None

    def list_entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{"key": k, **v} for k, v in self._store.items()]

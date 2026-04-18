"""HashiCorp Vault KV v2 backend for M06 Credential Vault (M06_VAULT_BACKEND=vault)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class HCVaultBackend:
    """
    Persists secrets in HashiCorp Vault KV v2.

    Each secret lives at {mount}/data/{kv_path}/{key}.
    Status, owner, tenant, and timestamps are stored inside the secret payload
    so they survive without requiring Vault Enterprise metadata APIs.
    """

    def __init__(self, addr: str, token: str, mount: str, kv_path: str) -> None:
        try:
            import hvac  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "hvac package required for VaultBackend — pip install hvac"
            ) from exc

        self._client = hvac.Client(url=addr, token=token)
        self._mount = mount
        self._kv_path = kv_path

        if not self._client.is_authenticated():
            raise RuntimeError(
                f"Vault token invalid or expired for addr={addr}"
            )
        logger.info("HCVaultBackend connected addr=%s mount=%s", addr, mount)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _path(self, key: str) -> str:
        return f"{self._kv_path}/{key}"

    @staticmethod
    def _parse_dt(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    def _read_raw(self, key: str) -> dict[str, Any] | None:
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                mount_point=self._mount,
                path=self._path(key),
                raise_on_deleted_version=True,
            )
            return resp["data"]["data"]
        except Exception as exc:
            cls = type(exc).__name__
            if "404" in str(exc) or "InvalidPath" in cls or "VaultError" in cls:
                return None
            logger.warning("Vault read failed key='%s': %s", key, exc)
            return None

    def _write_raw(self, key: str, payload: dict[str, Any]) -> None:
        # Serialise datetime objects to ISO strings for Vault storage
        serialisable = {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in payload.items()
        }
        self._client.secrets.kv.v2.create_or_update_secret(
            mount_point=self._mount,
            path=self._path(key),
            secret=serialisable,
        )

    # VaultBackend protocol
    # ------------------------------------------------------------------

    def store(
        self, key: str, value: str, owner_module: str = "", tenant_id: str = ""
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "value": value,
            "status": "active",
            "created_at": now,
            "rotated_at": now,
            "owner_module": owner_module,
            "tenant_id": tenant_id,
        }
        self._write_raw(key, payload)
        return payload

    def read(self, key: str) -> str | None:
        entry = self.get_entry(key)
        if entry and entry.get("status") == "active":
            return entry.get("value")
        return None

    def rotate(self, key: str, new_value: str) -> dict[str, Any] | None:
        entry = self.get_entry(key)
        if entry is None:
            return None
        now = datetime.now(timezone.utc)
        entry["value"] = new_value
        entry["rotated_at"] = now
        entry["status"] = "active"
        # Exclude the synthetic "key" field before writing back
        payload = {k: v for k, v in entry.items() if k != "key"}
        self._write_raw(key, payload)
        return entry

    def revoke(self, key: str) -> bool:
        entry = self.get_entry(key)
        if entry is None:
            return False
        payload = {k: v for k, v in entry.items() if k != "key"}
        payload["status"] = "revoked"
        self._write_raw(key, payload)
        return True

    def get_entry(self, key: str) -> dict[str, Any] | None:
        raw = self._read_raw(key)
        if raw is None:
            return None
        # Restore datetime objects
        for field in ("created_at", "rotated_at"):
            raw[field] = self._parse_dt(raw.get(field))
        return {"key": key, **raw}

    def list_entries(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.secrets.kv.v2.list_secrets(
                mount_point=self._mount,
                path=self._kv_path,
            )
            keys: list[str] = resp.get("data", {}).get("keys", [])
        except Exception as exc:
            logger.warning("Vault list failed: %s", exc)
            return []

        entries = []
        for k in keys:
            if k.endswith("/"):
                continue  # skip subdirectories
            entry = self.get_entry(k)
            if entry:
                entries.append(entry)
        return entries

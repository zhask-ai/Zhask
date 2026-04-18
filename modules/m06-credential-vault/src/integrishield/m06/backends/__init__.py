"""Backend protocol and factory for M06 Credential Vault."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class VaultBackend(Protocol):
    """Minimal contract every vault backend must satisfy."""

    def store(self, key: str, value: str, owner_module: str, tenant_id: str) -> dict[str, Any]: ...
    def read(self, key: str) -> str | None: ...
    def rotate(self, key: str, new_value: str) -> dict[str, Any] | None: ...
    def revoke(self, key: str) -> bool: ...
    def get_entry(self, key: str) -> dict[str, Any] | None: ...
    def list_entries(self) -> list[dict[str, Any]]: ...


def get_backend() -> VaultBackend:
    """Return the configured backend singleton."""
    from integrishield.m06.config import settings  # noqa: PLC0415

    if settings.vault_backend == "vault":
        from integrishield.m06.backends.vault import HCVaultBackend  # noqa: PLC0415

        return HCVaultBackend(
            addr=settings.vault_addr,
            token=settings.vault_token,
            mount=settings.vault_mount,
            kv_path=settings.vault_kv_path,
        )
    from integrishield.m06.backends.memory import MemoryBackend  # noqa: PLC0415

    return MemoryBackend()

"""API routes — credential management endpoints for M06 Credential Vault."""

from fastapi import APIRouter, HTTPException

from integrishield.m06.models import (
    RotateRequest,
    RotateResponse,
    RevokeResponse,
    SecretMetadata,
    VaultStatsResponse,
)
from integrishield.m06.services import (
    get_stats,
    list_secrets,
    read_secret,
    revoke_secret,
    rotate_secret,
    store_secret,
)

router = APIRouter(prefix="/api/v1/vault", tags=["credential-vault"])


@router.post("/secrets", response_model=SecretMetadata, status_code=201)
async def create_secret(key: str, owner_module: str = "", tenant_id: str = ""):
    """Store a new secret (value is auto-generated)."""
    import secrets as stdlib_secrets  # noqa: PLC0415

    value = stdlib_secrets.token_urlsafe(32)
    return store_secret(key, value, owner_module, tenant_id)


@router.get("/secrets", response_model=list[SecretMetadata])
async def list_all():
    """List metadata for all stored secrets (values never exposed)."""
    return list_secrets()


@router.get("/secrets/{key}", response_model=SecretMetadata)
async def get_secret_metadata(key: str):
    """Return metadata for a single secret."""
    from integrishield.m06.services import _get_backend  # noqa: PLC0415

    entry = _get_backend().get_entry(key)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Secret '{key}' not found")
    from integrishield.m06.services import _entry_to_metadata  # noqa: PLC0415

    return _entry_to_metadata(key, entry)


@router.get("/secrets/{key}/value")
async def read_secret_value(key: str, requester: str = ""):
    """Return the raw secret value — restricted; every call is audit-logged."""
    value = read_secret(key, requester=requester)
    if value is None:
        raise HTTPException(status_code=404, detail=f"Secret '{key}' not found or revoked")
    return {"key": key, "value": value}


@router.post("/secrets/rotate", response_model=RotateResponse)
async def rotate(req: RotateRequest):
    """Rotate an existing secret with a newly generated value."""
    import secrets as stdlib_secrets  # noqa: PLC0415

    new_value = stdlib_secrets.token_urlsafe(32)
    result = rotate_secret(req.key, new_value, req.reason)
    if not result.rotated:
        raise HTTPException(status_code=404, detail=f"Secret '{req.key}' not found")
    return result


@router.delete("/secrets/{key}", response_model=RevokeResponse)
async def revoke(key: str):
    """Revoke a secret — marks it inactive and audit-logs the action."""
    ok = revoke_secret(key)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Secret '{key}' not found")
    return RevokeResponse(key=key, revoked=True)


@router.get("/stats", response_model=VaultStatsResponse)
async def vault_stats():
    """Vault health statistics."""
    return VaultStatsResponse(**get_stats())

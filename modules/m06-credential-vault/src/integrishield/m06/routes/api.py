"""API routes — credential management endpoints for M06 Credential Vault."""

from fastapi import APIRouter

from integrishield.m06.models import RotateRequest, RotateResponse, SecretMetadata, VaultStatsResponse
from integrishield.m06.services import get_stats, list_secrets, rotate_secret, store_secret

router = APIRouter(prefix="/api/v1/vault", tags=["credential-vault"])


@router.post("/secrets", response_model=SecretMetadata)
async def create_secret(key: str, owner_module: str = "", tenant_id: str = ""):
    """Store a new secret (value is auto-generated in POC)."""
    import secrets as stdlib_secrets

    value = stdlib_secrets.token_urlsafe(32)
    return store_secret(key, value, owner_module, tenant_id)


@router.post("/secrets/rotate", response_model=RotateResponse)
async def rotate(req: RotateRequest):
    """Rotate an existing secret."""
    import secrets as stdlib_secrets

    new_value = stdlib_secrets.token_urlsafe(32)
    return rotate_secret(req.key, new_value, req.reason)


@router.get("/secrets", response_model=list[SecretMetadata])
async def list_all():
    """List metadata for all stored secrets."""
    return list_secrets()


@router.get("/stats", response_model=VaultStatsResponse)
async def vault_stats():
    """Vault health statistics."""
    return VaultStatsResponse(**get_stats())

"""
shared.auth.api_key
--------------------
POC API-key authentication.

How it works
------------
A valid API key is any value in the comma-separated INTEGRISHIELD_API_KEYS
environment variable.  For the POC, set one key in .env:

    INTEGRISHIELD_API_KEYS=poc-dev-key-abc123

Callers use this in two ways:

1. Programmatic (service-to-service, tests):
       verify_api_key("poc-dev-key-abc123")  # raises APIKeyError if invalid

2. FastAPI dependency (M01 routes):
       from fastapi import Depends
       from shared.auth import require_api_key

       @router.post("/rfc/proxy")
       async def proxy(key: str = Depends(require_api_key)):
           ...

Post-POC migration path
-----------------------
Replace this module with a JWT verifier — the FastAPI Depends() pattern
stays identical, so no route code changes.

Owned by Dev 1.
"""

import os
import secrets
from functools import lru_cache

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from shared.telemetry import get_logger

logger = get_logger(__name__)

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_ENV_VAR = "INTEGRISHIELD_API_KEYS"


class APIKeyError(Exception):
    """Raised when an API key is missing or invalid."""


@lru_cache(maxsize=1)
def _valid_keys() -> frozenset[str]:
    """
    Load valid keys from the environment (cached after first call).
    Supports multiple keys (comma-separated) for key rotation.
    """
    raw = os.getenv(_ENV_VAR, "")
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    if not keys:
        logger.warning(
            "No API keys configured in %s — all requests will be rejected", _ENV_VAR
        )
    return frozenset(keys)


def verify_api_key(key: str | None) -> str:
    """
    Verify *key* against the configured valid keys.

    Returns the key on success so callers can log it (partially).
    Raises APIKeyError on failure.
    """
    if not key:
        raise APIKeyError("Missing X-API-Key header")
    valid = _valid_keys()
    # Use constant-time comparison to prevent timing attacks.
    for valid_key in valid:
        if secrets.compare_digest(key, valid_key):
            return key
    raise APIKeyError("Invalid API key")


async def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> str:
    """
    FastAPI dependency.  Inject with Depends(require_api_key).
    Raises HTTP 401 on failure.
    """
    try:
        return verify_api_key(api_key)
    except APIKeyError as exc:
        logger.warning("Auth failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "ApiKey"},
        ) from exc

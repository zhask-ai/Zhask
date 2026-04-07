"""JWT validation for IntegriShield.

Validates RS256 JSON Web Tokens against a JWKS endpoint.
POC mode: If no JWKS_URL is configured, tokens are decoded WITHOUT
signature verification so the system can run locally without an IdP.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

JWKS_URL = os.getenv("JWKS_URL", "")  # empty = POC mode (skip verification)
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "integrishield-api")
JWT_ISSUER = os.getenv("JWT_ISSUER", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")

# ---------------------------------------------------------------------------
# Token claims
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenClaims:
    """Parsed JWT claims used throughout the platform."""

    sub: str
    tenant_id: str = ""
    scopes: list[str] = field(default_factory=list)
    exp: int = 0
    iat: int = 0
    iss: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_expired(self) -> bool:
        if self.exp == 0:
            return False
        return time.time() > self.exp


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class JWTValidator:
    """Validates and decodes JWT tokens.

    In POC mode (no JWKS_URL), tokens are base64-decoded without
    cryptographic verification. In production, set JWKS_URL to enable
    full RS256 signature validation.
    """

    def __init__(
        self,
        jwks_url: str = JWKS_URL,
        audience: str = JWT_AUDIENCE,
        issuer: str = JWT_ISSUER,
    ):
        self.jwks_url = jwks_url
        self.audience = audience
        self.issuer = issuer
        self._poc_mode = not bool(jwks_url)

        if self._poc_mode:
            logger.warning(
                "JWT validator running in POC mode — tokens are NOT cryptographically verified. "
                "Set JWKS_URL to enable production validation."
            )

    def validate(self, token: str) -> TokenClaims:
        """Validate a JWT and return parsed claims.

        Raises ValueError if the token is invalid or expired.
        """
        if self._poc_mode:
            return self._decode_poc(token)
        return self._decode_production(token)

    def _decode_poc(self, token: str) -> TokenClaims:
        """POC: decode the payload without signature verification."""
        import base64

        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format — expected 3 dot-separated parts")

        try:
            # Pad the base64url payload
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            claims = json.loads(payload_bytes)
        except Exception as exc:
            raise ValueError(f"Failed to decode JWT payload: {exc}") from exc

        parsed = TokenClaims(
            sub=claims.get("sub", "anonymous"),
            tenant_id=claims.get("tenant_id", claims.get("tid", "")),
            scopes=claims.get("scope", "").split() if isinstance(claims.get("scope"), str) else claims.get("scopes", []),
            exp=claims.get("exp", 0),
            iat=claims.get("iat", 0),
            iss=claims.get("iss", ""),
            raw=claims,
        )

        if parsed.is_expired:
            raise ValueError("Token has expired")

        return parsed

    def _decode_production(self, token: str) -> TokenClaims:
        """Production: full RS256 validation against JWKS endpoint.

        Requires PyJWT[crypto]: pip install PyJWT[crypto]
        """
        try:
            import jwt
            from jwt import PyJWKClient
        except ImportError as exc:
            raise RuntimeError(
                "PyJWT[crypto] is required for production JWT validation. "
                "Install it: pip install 'PyJWT[crypto]'"
            ) from exc

        jwks_client = PyJWKClient(self.jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        decode_options: dict[str, Any] = {}
        if not self.audience:
            decode_options["verify_aud"] = False

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=[JWT_ALGORITHM],
            audience=self.audience or None,
            issuer=self.issuer or None,
            options=decode_options,
        )

        return TokenClaims(
            sub=claims.get("sub", ""),
            tenant_id=claims.get("tenant_id", claims.get("tid", "")),
            scopes=claims.get("scope", "").split() if isinstance(claims.get("scope"), str) else claims.get("scopes", []),
            exp=claims.get("exp", 0),
            iat=claims.get("iat", 0),
            iss=claims.get("iss", ""),
            raw=claims,
        )


# Module-level singleton
_default_validator: JWTValidator | None = None


def get_validator() -> JWTValidator:
    global _default_validator
    if _default_validator is None:
        _default_validator = JWTValidator()
    return _default_validator

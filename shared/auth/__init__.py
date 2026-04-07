"""
shared.auth — authentication helpers for IntegriShield modules.
Owned by Dev 1.

POC: simple API-key check via X-API-Key header.
Post-funding: swap in JWT / OAuth2 without changing call-sites
              (callers only import verify_api_key or require_api_key).
"""

from shared.auth.api_key import verify_api_key, require_api_key, APIKeyError

__all__ = ["verify_api_key", "require_api_key", "APIKeyError"]

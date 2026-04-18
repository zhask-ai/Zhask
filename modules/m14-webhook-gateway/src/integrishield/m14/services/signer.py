"""HMAC-SHA256 request signing for M14 Webhook Gateway."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def sign_payload(payload: dict[str, Any], secret: str) -> str:
    """Return HMAC-SHA256 hex digest of the JSON-serialised payload."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def signature_header(payload: dict[str, Any], secret: str) -> dict[str, str]:
    """Return the X-IntegriShield-Signature header dict, or empty dict if no secret."""
    if not secret:
        return {}
    sig = sign_payload(payload, secret)
    return {"X-IntegriShield-Signature": f"sha256={sig}"}

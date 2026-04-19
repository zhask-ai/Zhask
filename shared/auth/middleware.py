"""FastAPI auth middleware for IntegriShield.

Composes JWT validation + tenant extraction into a single middleware
that every module mounts in their app factory.

Usage:
    from shared.auth.middleware import AuthMiddleware

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
"""

from __future__ import annotations

import logging
import os
from typing import Callable

logger = logging.getLogger(__name__)

# Paths that bypass authentication
_PUBLIC_PATHS = frozenset({"/healthz", "/readyz", "/health", "/api/health", "/docs", "/openapi.json", "/favicon.ico"})

POC_MODE = os.getenv("AUTH_POC_MODE", "true").lower() in {"1", "true", "yes"}


class AuthMiddleware:
    """ASGI middleware that validates JWT and extracts tenant ID.

    In POC mode (default), requests without tokens are allowed through
    with a default tenant. In production mode, a valid Bearer token
    is required on all non-public paths.
    """

    def __init__(self, app, poc_mode: bool = POC_MODE):
        self.app = app
        self.poc_mode = poc_mode

        if self.poc_mode:
            logger.info("Auth middleware running in POC mode — unauthenticated requests allowed")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Public endpoints bypass auth
        if path in _PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        # Decode bytes headers to str
        str_headers = {}
        for k, v in headers.items():
            key = k.decode("utf-8") if isinstance(k, bytes) else k
            val = v.decode("utf-8") if isinstance(v, bytes) else v
            str_headers[key] = val

        # Extract tenant ID
        from shared.auth.tenant import TenantError, extract_tenant_id

        try:
            tenant_id = extract_tenant_id(str_headers, poc_mode=self.poc_mode)
        except TenantError as exc:
            await self._send_error(send, 403, f"Tenant error: {exc}")
            return

        # Extract and validate JWT (if present)
        auth_header = str_headers.get("authorization", "")
        claims = None

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            from shared.auth.jwt_validator import get_validator

            try:
                claims = get_validator().validate(token)
            except ValueError as exc:
                await self._send_error(send, 401, f"Authentication failed: {exc}")
                return
        elif not self.poc_mode:
            await self._send_error(send, 401, "Missing Authorization header")
            return

        # Inject tenant_id and claims into ASGI scope for downstream use
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["tenant_id"] = tenant_id
        scope["state"]["claims"] = claims

        await self.app(scope, receive, send)

    async def _send_error(self, send: Callable, status: int, message: str) -> None:
        import json

        body = json.dumps({"error": message}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })

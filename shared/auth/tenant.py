"""Tenant ID extraction and validation.

Every request to an IntegriShield module MUST carry a tenant identifier.
This module extracts it from the X-Tenant-ID header and validates the format.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Tenant IDs must be alphanumeric + hyphens, 3-64 chars
_TENANT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{2,63}$")

# Default tenant for POC — used when no header is present and POC mode is on
DEFAULT_POC_TENANT = "poc-default"


class TenantError(Exception):
    """Raised when tenant validation fails."""


def validate_tenant_id(tenant_id: str) -> str:
    """Validate and normalise a tenant ID.

    Returns the lowercased tenant ID.
    Raises TenantError if invalid.
    """
    if not tenant_id:
        raise TenantError("Tenant ID is required")

    tenant_id = tenant_id.strip().lower()

    if not _TENANT_RE.match(tenant_id):
        raise TenantError(
            f"Invalid tenant ID '{tenant_id}'. Must be 3-64 alphanumeric characters (hyphens allowed, "
            f"must start with alphanumeric)."
        )

    return tenant_id


def extract_tenant_id(headers: dict[str, str], *, poc_mode: bool = True) -> str:
    """Extract tenant ID from request headers.

    Looks for 'X-Tenant-ID' header (case-insensitive).
    In POC mode, returns a default tenant if the header is missing.
    In production mode, raises TenantError if missing.
    """
    # Case-insensitive header lookup
    for key, value in headers.items():
        if key.lower() == "x-tenant-id":
            return validate_tenant_id(value)

    if poc_mode:
        logger.debug("No X-Tenant-ID header — using POC default '%s'", DEFAULT_POC_TENANT)
        return DEFAULT_POC_TENANT

    raise TenantError("Missing required X-Tenant-ID header")


def validate_tenant_header(headers: dict[str, str]) -> str:
    """Convenience alias — validates and returns tenant ID from headers."""
    return extract_tenant_id(headers, poc_mode=True)

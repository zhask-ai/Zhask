"""
Known SAP RFC endpoint allowlist.

Hardcoded for the POC. In production, load from a SAP system catalogue
or the KNOWN_ENDPOINTS_FILE env var (a JSON array of function names).
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_HARDCODED_KNOWN: frozenset[str] = frozenset(
    [
        "RFC_READ_TABLE",
        "BAPI_MATERIAL_GETLIST",
        "BAPI_CUSTOMER_GETLIST",
        "BAPI_SALESORDER_GETLIST",
        "BAPI_PO_GETDETAIL",
        "RFC_GET_SYSTEM_INFO",
        "SUSR_USER_AUTH_FOR_OBJ_GET",
        "BAPI_USER_GETLIST",
        "BAPI_COMPANYCODE_GETLIST",
        "RFC_FUNCTION_SEARCH",
        "BAPI_EMPLOYEE_GETDATA",
        "BAPI_VENDOR_GETLIST",
        "BAPI_PRODORD_GET_DETAIL",
        "RFC_PING",
        "STFC_CONNECTION",
        # Common ABAP test/diagnostic functions
        "FUNCTION_EXISTS",
        "SYSTEM_CALLSTACK",
        "RFC_SYSTEM_INFO",
        "TH_USER_LIST",
    ]
)


def load_registry(known_endpoints_file: str = "") -> frozenset[str]:
    """
    Load the set of known RFC functions.
    If known_endpoints_file is provided and exists, merge with hardcoded list.
    """
    endpoints = set(_HARDCODED_KNOWN)

    if known_endpoints_file:
        path = Path(known_endpoints_file)
        if path.exists():
            with open(path) as f:
                extra = json.load(f)
            if isinstance(extra, list):
                endpoints.update(extra)
                logger.info("Loaded %d extra endpoints from %s", len(extra), path)
            else:
                logger.warning("KNOWN_ENDPOINTS_FILE must be a JSON array, ignoring")
        else:
            logger.warning("KNOWN_ENDPOINTS_FILE '%s' not found, using defaults", path)

    return frozenset(endpoints)

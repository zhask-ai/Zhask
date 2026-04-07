"""Credential scanner — detects hardcoded passwords, API keys, tokens in ABAP code."""

from __future__ import annotations

import re
import uuid

from integrishield.m13.models import ScanFinding, VulnCategory, VulnSeverity

# Compiled patterns: (pattern, description, remediation)
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"""(?i)password\s*=\s*['"][^'"]{4,}['"]"""),
        "Hardcoded password detected in string assignment",
        "Use SAP Secure Storage (SSFX) or environment-specific secret management instead of hardcoded credentials.",
    ),
    (
        re.compile(r"""(?i)passwd\s*=\s*['"][^'"]{4,}['"]"""),
        "Hardcoded passwd field detected",
        "Replace hardcoded passwd with a runtime-resolved secret from SAP Credential Store.",
    ),
    (
        re.compile(r"""(?i)api[_-]?key\s*=\s*['"][A-Za-z0-9\-_]{8,}['"]"""),
        "Hardcoded API key detected",
        "Store API keys in SAP BTP Credential Store or an external vault, not in source code.",
    ),
    (
        re.compile(r"""(?i)client[_-]?secret\s*=\s*['"][^'"]{8,}['"]"""),
        "Hardcoded client secret detected",
        "Rotate the secret immediately and store it in a secrets manager.",
    ),
    (
        re.compile(r"""(?i)(token|auth[_-]?token|bearer)\s*=\s*['"][A-Za-z0-9+/=._\-]{16,}['"]"""),
        "Hardcoded authentication token detected",
        "Authentication tokens must not be embedded in source code. Use runtime token exchange.",
    ),
    (
        re.compile(r"""(?i)(access[_-]?key|secret[_-]?key)\s*=\s*['"][A-Za-z0-9+/=]{16,}['"]"""),
        "Hardcoded access/secret key detected",
        "Cloud access keys must not appear in ABAP code. Use IAM roles or SAP credential binding.",
    ),
]


def scan(scan_id: str, code: str) -> list[ScanFinding]:
    """Scan ABAP code for hardcoded credentials.

    Returns a list of ScanFinding objects, one per match.
    Snippets are truncated/redacted to avoid logging actual secrets.
    """
    findings: list[ScanFinding] = []
    lines = code.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for pattern, description, remediation in _CREDENTIAL_PATTERNS:
            match = pattern.search(line)
            if match:
                # Redact the actual value from snippet — show only up to the '=' sign
                raw = line.strip()
                eq_pos = raw.find("=")
                snippet = (raw[: eq_pos + 2] + "***REDACTED***") if eq_pos >= 0 else raw[:60]

                findings.append(
                    ScanFinding(
                        finding_id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        category=VulnCategory.HARDCODED_CREDENTIAL,
                        severity=VulnSeverity.CRITICAL,
                        line_number=lineno,
                        snippet=snippet[:200],
                        description=description,
                        remediation=remediation,
                    )
                )
                break  # one finding per line maximum

    return findings

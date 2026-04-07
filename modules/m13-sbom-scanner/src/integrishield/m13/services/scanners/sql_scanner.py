"""SQL injection scanner — detects ABAP-specific SQL injection patterns."""

from __future__ import annotations

import re
import uuid

from integrishield.m13.models import ScanFinding, VulnCategory, VulnSeverity

# Pattern: EXEC SQL ... (native SQL execution)
_EXEC_SQL = re.compile(r"""(?i)\bEXEC\s+SQL\b""")

# Pattern: dynamic WHERE clause via string concatenation (&, &&, +=)
_DYNAMIC_WHERE = re.compile(r"""(?i)\bWHERE\b.*[&]""")

# Pattern: FIELD-SYMBOLS used in SELECT (potential dynamic column selection)
_FIELD_SYMBOLS_SELECT = re.compile(r"""(?i)SELECT\s+.*<\w+>""")

# Pattern: dynamic SELECT string built with concatenate/&&
_DYNAMIC_SELECT = re.compile(r"""(?i)CONCATENATE.*SELECT|SELECT.*CONCATENATE""")

# Pattern: (sy-uname) or user input used directly in SQL WHERE
_USER_INPUT_WHERE = re.compile(r"""(?i)WHERE.*sy-(?:uname|datum|uzeit|mandt)""")

_PATTERNS: list[tuple[re.Pattern, str, str, VulnSeverity]] = [
    (
        _EXEC_SQL,
        "Native SQL execution (EXEC SQL) detected — bypasses ABAP SQL safety layer",
        "Use Open SQL (SELECT/INSERT/UPDATE) instead of EXEC SQL. Native SQL bypasses input sanitisation.",
        VulnSeverity.HIGH,
    ),
    (
        _DYNAMIC_WHERE,
        "Dynamic WHERE clause built with string concatenation — potential SQL injection",
        "Use typed parameters and WHERE conditions with typed variables, not string concatenation.",
        VulnSeverity.HIGH,
    ),
    (
        _FIELD_SYMBOLS_SELECT,
        "FIELD-SYMBOLS used as SELECT column target — potential dynamic column injection",
        "Avoid using FIELD-SYMBOLS as column references in SELECT statements. Use explicit field lists.",
        VulnSeverity.MEDIUM,
    ),
    (
        _DYNAMIC_SELECT,
        "SELECT statement built with CONCATENATE — dynamic query construction risk",
        "Avoid building SELECT statements dynamically with CONCATENATE. Use parameterised queries.",
        VulnSeverity.HIGH,
    ),
    (
        _USER_INPUT_WHERE,
        "System variable (sy-*) used directly in SQL WHERE clause",
        "Validate and sanitise all sy-* fields before using them in SQL conditions.",
        VulnSeverity.MEDIUM,
    ),
]


def scan(scan_id: str, code: str) -> list[ScanFinding]:
    """Scan ABAP code for SQL injection patterns."""
    findings: list[ScanFinding] = []
    lines = code.splitlines()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):  # skip comment lines
            continue
        for pattern, description, remediation, severity in _PATTERNS:
            if pattern.search(line):
                findings.append(
                    ScanFinding(
                        finding_id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        category=VulnCategory.SQL_INJECTION,
                        severity=severity,
                        line_number=lineno,
                        snippet=stripped[:200],
                        description=description,
                        remediation=remediation,
                    )
                )
                break  # one finding per line

    return findings

"""RFC scanner — detects calls to insecure/dangerous SAP function modules."""

from __future__ import annotations

import re
import uuid

from integrishield.m13.models import ScanFinding, VulnCategory, VulnSeverity

# Regex to extract function module name from CALL FUNCTION statements
_CALL_FUNCTION_RE = re.compile(r"""(?i)CALL\s+FUNCTION\s+['"]([A-Z0-9_/]+)['"]""")

# Default blocklist with severity + remediation notes
_RFC_BLOCKLIST: dict[str, tuple[VulnSeverity, str, str]] = {
    "RFC_READ_TABLE": (
        VulnSeverity.HIGH,
        "RFC_READ_TABLE allows unrestricted table reads and is a common data exfiltration vector.",
        "Restrict access via authorisation object S_TABU_DIS. Consider replacing with a custom, authorised FM.",
    ),
    "BAPI_USER_CHANGE": (
        VulnSeverity.CRITICAL,
        "BAPI_USER_CHANGE can modify any user account, including admin accounts.",
        "Restrict RFC access to this BAPI. Require dual approval workflow for user changes.",
    ),
    "BAPI_USER_CREATE": (
        VulnSeverity.CRITICAL,
        "BAPI_USER_CREATE can create privileged users remotely.",
        "Restrict RFC access. All user creation must go through the identity governance process.",
    ),
    "BAPI_USER_DELETE": (
        VulnSeverity.CRITICAL,
        "BAPI_USER_DELETE can remove user accounts, enabling account manipulation attacks.",
        "Restrict this BAPI to identity governance systems only.",
    ),
    "RFC_SYSTEM_INFO": (
        VulnSeverity.MEDIUM,
        "RFC_SYSTEM_INFO leaks SAP system configuration data to any RFC caller.",
        "Restrict RFC access to authorised monitoring systems only.",
    ),
    "TH_POPUP": (
        VulnSeverity.LOW,
        "TH_POPUP can send pop-up messages to logged-in users — social engineering risk.",
        "Restrict RFC access. Should only be callable from trusted monitoring systems.",
    ),
    "SE16_READ": (
        VulnSeverity.HIGH,
        "SE16_READ bypasses standard table authorisation checks.",
        "Do not expose SE16_READ via RFC. Use proper authorisation-checked data access.",
    ),
    "STRUST_MODIFY": (
        VulnSeverity.CRITICAL,
        "STRUST_MODIFY can modify SSL/TLS trust store — enables MITM attacks.",
        "Block external RFC access to STRUST_MODIFY. Changes require change management approval.",
    ),
    "SUSR_USER_AUTH_FOR_OBJ_GET": (
        VulnSeverity.HIGH,
        "SUSR_USER_AUTH_FOR_OBJ_GET exposes user authorisation data for enumeration.",
        "Restrict to internal security audit tools only.",
    ),
    "RFC_ABAP_INSTALL_AND_RUN": (
        VulnSeverity.CRITICAL,
        "RFC_ABAP_INSTALL_AND_RUN executes arbitrary ABAP code remotely — critical RCE risk.",
        "Block this function module at the RFC gateway. Should never be callable externally.",
    ),
    "SXPG_COMMAND_EXECUTE": (
        VulnSeverity.CRITICAL,
        "SXPG_COMMAND_EXECUTE runs OS commands on the SAP host — OS command injection risk.",
        "Remove RFC access. OS commands must only be triggered by authorised batch processes.",
    ),
    "SXPG_CALL_SYSTEM": (
        VulnSeverity.CRITICAL,
        "SXPG_CALL_SYSTEM executes system-level commands — OS command injection risk.",
        "Block at RFC gateway layer. Never expose system command execution via RFC.",
    ),
}


def scan(scan_id: str, code: str, extra_blocklist: set[str] | None = None) -> list[ScanFinding]:
    """Scan ABAP code for calls to insecure RFC function modules."""
    blocklist = _RFC_BLOCKLIST.copy()
    if extra_blocklist:
        for fm in extra_blocklist:
            if fm not in blocklist:
                blocklist[fm] = (
                    VulnSeverity.HIGH,
                    f"Call to potentially insecure function module: {fm}",
                    "Review whether this function module should be called from this context.",
                )

    findings: list[ScanFinding] = []
    lines = code.splitlines()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):
            continue
        for match in _CALL_FUNCTION_RE.finditer(line):
            fm_name = match.group(1).upper()
            if fm_name in blocklist:
                severity, description, remediation = blocklist[fm_name]
                findings.append(
                    ScanFinding(
                        finding_id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        category=VulnCategory.INSECURE_RFC,
                        severity=severity,
                        line_number=lineno,
                        snippet=stripped[:200],
                        description=f"Call to {fm_name}: {description}",
                        remediation=remediation,
                    )
                )

    return findings


def get_blocklist() -> dict[str, dict]:
    """Return the blocklist as a list of dicts for the /rules endpoint."""
    return {
        fm: {
            "function_module": fm,
            "severity": sev.value,
            "description": desc,
            "remediation": rem,
        }
        for fm, (sev, desc, rem) in _RFC_BLOCKLIST.items()
    }

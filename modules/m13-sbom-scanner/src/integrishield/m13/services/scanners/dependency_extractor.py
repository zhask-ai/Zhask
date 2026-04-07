"""Dependency extractor — identifies ABAP INCLUDE/CALL FUNCTION dependencies and correlates CVEs."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from integrishield.m13.models import SbomComponent, ScanFinding, VulnCategory, VulnSeverity

# INCLUDE statement
_INCLUDE_RE = re.compile(r"""(?i)^\s*INCLUDE\s+([A-Z0-9_/]+)\s*\.""")

# CALL FUNCTION (captures namespace + FM name)
_CALL_FM_RE = re.compile(r"""(?i)CALL\s+FUNCTION\s+['"]([A-Z0-9_/]+)['"]""")

# Third-party / customer namespace: starts with /
_PARTNER_NS_RE = re.compile(r"""^/[A-Z0-9]+/""")

# CLASS ... DEFINITION patterns
_CLASS_DEF_RE = re.compile(r"""(?i)CLASS\s+(\S+)\s+DEFINITION""")

# Cached CVE stubs: loaded once from file
_cve_stubs: dict[str, list[dict]] = {}


def load_cve_stubs(path: str) -> None:
    """Load CVE stub database from a JSON file. Call once at startup."""
    global _cve_stubs
    try:
        data = json.loads(Path(path).read_text())
        # Expected format: {"RFC_READ_TABLE": [{"cve_id": "...", "cvss": 7.5, "summary": "..."}], ...}
        _cve_stubs = data
    except Exception:
        _cve_stubs = {}


def _get_cves_for(name: str) -> list[str]:
    """Return CVE IDs for a given component name."""
    upper = name.upper()
    entries = _cve_stubs.get(upper, [])
    return [e["cve_id"] for e in entries if "cve_id" in e]


def extract(scan_id: str, code: str) -> tuple[list[SbomComponent], list[ScanFinding]]:
    """Extract dependencies from ABAP code and cross-reference CVEs.

    Returns (components, findings) where findings are CVE-matched vulnerabilities.
    """
    components: list[SbomComponent] = []
    findings: list[ScanFinding] = []
    seen_names: set[str] = set()

    lines = code.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):
            continue

        # INCLUDE dependencies
        include_match = _INCLUDE_RE.match(line)
        if include_match:
            name = include_match.group(1)
            if name not in seen_names:
                seen_names.add(name)
                cve_ids = _get_cves_for(name)
                comp = SbomComponent(
                    type="library",
                    name=name,
                    purl=f"pkg:abap/{name.lower()}",
                    cve_ids=cve_ids,
                )
                components.append(comp)
                _add_cve_findings(findings, scan_id, name, cve_ids, lineno, stripped)

        # CALL FUNCTION — third-party namespace only
        for fm_match in _CALL_FM_RE.finditer(line):
            fm_name = fm_match.group(1)
            if _PARTNER_NS_RE.match(fm_name) and fm_name not in seen_names:
                seen_names.add(fm_name)
                cve_ids = _get_cves_for(fm_name)
                comp = SbomComponent(
                    type="library",
                    name=fm_name,
                    purl=f"pkg:abap/{fm_name.lower().replace('/', '-')}",
                    cve_ids=cve_ids,
                )
                components.append(comp)
                _add_cve_findings(findings, scan_id, fm_name, cve_ids, lineno, stripped)

        # CLASS DEFINITION
        class_match = _CLASS_DEF_RE.search(line)
        if class_match:
            cls_name = class_match.group(1)
            if _PARTNER_NS_RE.match(cls_name) and cls_name not in seen_names:
                seen_names.add(cls_name)
                cve_ids = _get_cves_for(cls_name)
                comp = SbomComponent(
                    type="library",
                    name=cls_name,
                    purl=f"pkg:abap/{cls_name.lower().replace('/', '-')}",
                    cve_ids=cve_ids,
                )
                components.append(comp)
                _add_cve_findings(findings, scan_id, cls_name, cve_ids, lineno, stripped)

    return components, findings


def _add_cve_findings(
    findings: list[ScanFinding],
    scan_id: str,
    name: str,
    cve_ids: list[str],
    lineno: int,
    snippet: str,
) -> None:
    for cve_id in cve_ids:
        stub_entry = next(
            (e for e in _cve_stubs.get(name.upper(), []) if e.get("cve_id") == cve_id),
            {},
        )
        cvss = stub_entry.get("cvss", 0.0)
        severity = (
            VulnSeverity.CRITICAL
            if cvss >= 9.0
            else VulnSeverity.HIGH
            if cvss >= 7.0
            else VulnSeverity.MEDIUM
            if cvss >= 4.0
            else VulnSeverity.LOW
        )
        findings.append(
            ScanFinding(
                finding_id=str(uuid.uuid4()),
                scan_id=scan_id,
                category=VulnCategory.CVE_DEPENDENCY,
                severity=severity,
                line_number=lineno,
                snippet=snippet[:200],
                description=stub_entry.get(
                    "summary",
                    f"Dependency {name} has known vulnerability {cve_id}",
                ),
                cve_id=cve_id,
                remediation=f"Review {cve_id} and apply the vendor patch or replace the dependency.",
            )
        )

"""Dependency extractor — identifies ABAP INCLUDE/CALL FUNCTION dependencies and correlates CVEs.

CVE lookup order:
  1. SQLite cache (hot path, synchronous, <1ms)
  2. NVD 2.0 API (cache miss only; synchronous httpx call; results written to cache)
  3. OSV.dev API (cross-check on NVD miss; optional)

Set M13_VAULT_BACKEND=memory or configure cve_cache_db_path in settings to control persistence.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from integrishield.m13.models import SbomComponent, ScanFinding, VulnCategory, VulnSeverity

logger = logging.getLogger(__name__)

# INCLUDE statement
_INCLUDE_RE = re.compile(r"""(?i)^\s*INCLUDE\s+([A-Z0-9_/]+)\s*\.""")

# CALL FUNCTION (captures namespace + FM name)
_CALL_FM_RE = re.compile(r"""(?i)CALL\s+FUNCTION\s+['"]([A-Z0-9_/]+)['"]""")

# Third-party / customer namespace: starts with /
_PARTNER_NS_RE = re.compile(r"""^/[A-Z0-9]+/""")

# CLASS ... DEFINITION patterns
_CLASS_DEF_RE = re.compile(r"""(?i)CLASS\s+(\S+)\s+DEFINITION""")

# Module-level feed references — set up by init_feeds() on startup
_cache: Any = None   # CVECache instance
_nvd: Any = None     # NVDFeed instance
_osv: Any = None     # OSVFeed instance


def init_feeds(cache: Any, nvd: Any, osv: Any) -> None:
    """Inject feed instances at startup (called from main.py lifespan)."""
    global _cache, _nvd, _osv
    _cache = cache
    _nvd = nvd
    _osv = osv
    logger.info(
        "m13 CVE feeds initialised (cache=%s nvd=%s osv=%s)",
        type(cache).__name__,
        type(nvd).__name__,
        type(osv).__name__,
    )


# ---------------------------------------------------------------------------
# Legacy stub loader — kept for API compatibility with existing tests.
# When live feeds are configured, stubs are seeded into the cache.
# ---------------------------------------------------------------------------

def load_cve_stubs(path: str) -> None:
    """Load CVE stub JSON into the cache. No-op if live feeds already active."""
    if _cache is not None:
        logger.info("m13 live feeds active — ignoring cve_stubs_path")
        return
    import json  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    try:
        data: dict[str, list[dict]] = json.loads(Path(path).read_text())
        from integrishield.m13.feeds.cache import CVECache  # noqa: PLC0415
        from integrishield.m13.config import settings  # noqa: PLC0415

        stub_cache = CVECache(settings.cve_cache_db_path, ttl_hours=settings.cve_cache_ttl_hours)
        for component, cves in data.items():
            stub_cache.put(component, cves, source="stub")
        global _cache
        _cache = stub_cache
        logger.info("m13 loaded %d CVE stub entries from %s", len(data), path)
    except Exception as exc:
        logger.warning("m13 failed to load CVE stubs from %s: %s", path, exc)


def _get_cves_for(name: str) -> list[dict]:
    """Return CVE dicts for a component — cache-first, then live NVD/OSV lookup."""
    if _cache is None:
        return []

    cached = _cache.get(name)
    if cached is not None:
        return [c for c in cached if c.get("cve_id") != "__none__"]

    # Cache miss — query live feeds
    cves: list[dict] = []
    if _nvd is not None:
        try:
            cves = _nvd.lookup(name)
        except Exception as exc:
            logger.warning("NVD lookup error for '%s': %s", name, exc)

    if not cves and _osv is not None:
        try:
            cves = _osv.lookup(name)
        except Exception as exc:
            logger.warning("OSV lookup error for '%s': %s", name, exc)

    source = "nvd" if (cves and cves[0].get("source") == "nvd") else "osv"
    _cache.put(name, cves, source=source)
    return cves


def extract(scan_id: str, code: str) -> tuple[list[SbomComponent], list[ScanFinding]]:
    """Extract dependencies from ABAP code and cross-reference CVEs."""
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
                cve_dicts = _get_cves_for(name)
                comp = SbomComponent(
                    type="library",
                    name=name,
                    purl=f"pkg:abap/{name.lower()}",
                    cve_ids=[c["cve_id"] for c in cve_dicts],
                )
                components.append(comp)
                _add_cve_findings(findings, scan_id, name, cve_dicts, lineno, stripped)

        # CALL FUNCTION — third-party namespace only
        for fm_match in _CALL_FM_RE.finditer(line):
            fm_name = fm_match.group(1)
            if _PARTNER_NS_RE.match(fm_name) and fm_name not in seen_names:
                seen_names.add(fm_name)
                cve_dicts = _get_cves_for(fm_name)
                comp = SbomComponent(
                    type="library",
                    name=fm_name,
                    purl=f"pkg:abap/{fm_name.lower().replace('/', '-')}",
                    cve_ids=[c["cve_id"] for c in cve_dicts],
                )
                components.append(comp)
                _add_cve_findings(findings, scan_id, fm_name, cve_dicts, lineno, stripped)

        # CLASS DEFINITION
        class_match = _CLASS_DEF_RE.search(line)
        if class_match:
            cls_name = class_match.group(1)
            if _PARTNER_NS_RE.match(cls_name) and cls_name not in seen_names:
                seen_names.add(cls_name)
                cve_dicts = _get_cves_for(cls_name)
                comp = SbomComponent(
                    type="library",
                    name=cls_name,
                    purl=f"pkg:abap/{cls_name.lower().replace('/', '-')}",
                    cve_ids=[c["cve_id"] for c in cve_dicts],
                )
                components.append(comp)
                _add_cve_findings(findings, scan_id, cls_name, cve_dicts, lineno, stripped)

    return components, findings


def _add_cve_findings(
    findings: list[ScanFinding],
    scan_id: str,
    name: str,
    cve_dicts: list[dict],
    lineno: int,
    snippet: str,
) -> None:
    for entry in cve_dicts:
        cve_id = entry.get("cve_id", "")
        if not cve_id or cve_id == "__none__":
            continue
        cvss = float(entry.get("cvss", 0.0))
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
                description=entry.get(
                    "summary",
                    f"Dependency {name} has known vulnerability {cve_id}",
                ),
                cve_id=cve_id,
                remediation=(
                    f"Review {cve_id} (CVSS {cvss}) and apply the vendor patch "
                    "or replace the dependency."
                ),
            )
        )

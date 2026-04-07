"""CycloneDX 1.4 JSON SBOM builder."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from integrishield.m13.models import ScanResult


def build(result: ScanResult) -> dict:
    """Build a CycloneDX 1.4 JSON document from a completed ScanResult."""
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = (result.completed_at or datetime.now(tz=timezone.utc)).isoformat()

    components = []
    for comp in result.components:
        entry: dict = {
            "type": comp.type,
            "name": comp.name,
            "version": comp.version,
        }
        if comp.purl:
            entry["purl"] = comp.purl
        if comp.licenses:
            entry["licenses"] = [{"license": {"name": lic}} for lic in comp.licenses]

        # Embed vulnerability references
        if comp.cve_ids:
            entry["externalReferences"] = [
                {
                    "type": "advisories",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "comment": cve_id,
                }
                for cve_id in comp.cve_ids
            ]
        components.append(entry)

    # Build vulnerabilities section from findings that have CVE IDs
    vulnerabilities = []
    for finding in result.findings:
        if finding.cve_id:
            vulnerabilities.append(
                {
                    "id": finding.cve_id,
                    "ratings": [
                        {
                            "severity": finding.severity.value,
                            "method": "other",
                        }
                    ],
                    "description": finding.description,
                    "recommendation": finding.remediation,
                }
            )

    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "file",
                "name": result.filename,
                "version": "scanned",
            },
            "tools": [
                {
                    "vendor": "IntegriShield",
                    "name": "m13-sbom-scanner",
                    "version": "0.1.0",
                }
            ],
        },
        "components": components,
    }

    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities

    return sbom

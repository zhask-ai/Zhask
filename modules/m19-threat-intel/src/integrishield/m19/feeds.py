"""Feed pullers — POC uses small canned samples so the system is self-contained.

Production: replace with live HTTP pulls from
  - https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - https://epss.cyentia.com/epss_scores-current.csv.gz
  - https://osv.dev/v1/query
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_KEV_SAMPLE = {
    "CVE-2022-22536": {"name": "SAP ICM HTTP Smuggling", "added": "2022-02-11"},
    "CVE-2020-6287":  {"name": "SAP RECON", "added": "2021-11-03"},
    "CVE-2023-0669":  {"name": "Fortra GoAnywhere RCE", "added": "2023-02-02"},
}

_EPSS_SAMPLE = {
    "CVE-2022-22536": 0.974,
    "CVE-2020-6287": 0.962,
    "CVE-2023-0669": 0.944,
    "CVE-2021-44228": 0.975,
}

_SAP_NOTES_SAMPLE = {
    "3123396": {"title": "[CVE-2022-22536] ICM HTTP request smuggling", "priority": "HotNews", "cve_refs": ["CVE-2022-22536"]},
    "2934135": {"title": "[CVE-2020-6287] RECON — unauthenticated NetWeaver", "priority": "HotNews", "cve_refs": ["CVE-2020-6287"]},
}


def pull_kev() -> list[dict[str, Any]]:
    return [
        {"cve_id": cve, "kev": True, "kev_added_at": info["added"], "name": info["name"]}
        for cve, info in _KEV_SAMPLE.items()
    ]


def pull_epss() -> dict[str, float]:
    return dict(_EPSS_SAMPLE)


def pull_sap_notes() -> list[dict[str, Any]]:
    return [{"note_id": nid, **data} for nid, data in _SAP_NOTES_SAMPLE.items()]


def fuse() -> list[dict[str, Any]]:
    """Join KEV + EPSS + SAP Notes into enrichment records keyed by CVE."""
    out: dict[str, dict[str, Any]] = {}
    for item in pull_kev():
        cve = item["cve_id"]
        out[cve] = {"cve_id": cve, "kev": True, "sources": ["cisa-kev"]}
    for cve, epss in pull_epss().items():
        out.setdefault(cve, {"cve_id": cve, "kev": False, "sources": []})
        out[cve]["epss"] = epss
        out[cve]["sources"].append("epss")
    for note in pull_sap_notes():
        for cve in note["cve_refs"]:
            out.setdefault(cve, {"cve_id": cve, "kev": False, "sources": []})
            out[cve].setdefault("sap_note_refs", []).append(note["note_id"])
            out[cve]["sources"].append(f"sap-note:{note['note_id']}")
    now = datetime.now(timezone.utc).isoformat()
    for rec in out.values():
        rec["observed_at"] = now
    return list(out.values())

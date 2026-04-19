# M19 — Threat Intel Fusion

Fuses CISA KEV + EPSS + SAP Security Notes (+ OSV in production) into a
CVE-keyed enrichment cache. Other modules join against this at query time.

## Run

```bash
PYTHONPATH=modules/m19-threat-intel/src:shared \
  uvicorn integrishield.m19.main:app --reload --port 8019
```

## Endpoints

- `POST /intel/refresh` — pull all feeds (POC: canned samples)
- `GET  /intel/cves?kev=true&min_epss=0.9` — filter cached CVEs
- `GET  /intel/cve/{id}`
- `POST /intel/enrich` — bulk enrich a list of CVE IDs (used by M13)
- `GET  /intel/feeds/status`

## Integration points

- **M13 (SBOM)**: call `POST /intel/enrich` with CVEs found in a scan; surface
  `KEV` and `EPSS>0.9` badges on the dashboard.
- **M12 (Rules)**: `alert.severity = critical` if matched CVE has `kev=true`.
- **M10 (Incident)**: auto-escalate priority when KEV match is present.

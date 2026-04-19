# M17 — SAP SoD Violation Graph

Evaluates users' role→tcode assignments against a seeded Segregation-of-Duties
ruleset and emits `sod_violation` events for M12 / M10 / dashboard.

## Run

```bash
PYTHONPATH=modules/m17-sod-analyzer/src:shared \
  uvicorn integrishield.m17.main:app --reload --port 8017
```

## Minimal demo

```bash
curl -X POST :8017/sod/role-map -H 'content-type: application/json' \
  -d '{"role":"Z_AP_CLERK","tcodes":["FB60","F110"]}'
curl -X POST :8017/sod/role-map -H 'content-type: application/json' \
  -d '{"role":"Z_VENDOR_MAINT","tcodes":["XK01","FK01"]}'
curl -X POST :8017/sod/user-roles -H 'content-type: application/json' \
  -d '{"sap_user":"JDOE","roles":["Z_AP_CLERK","Z_VENDOR_MAINT"]}'
curl -X POST :8017/sod/recompute
curl :8017/sod/violations
```

## Risks shipped

See `config/risks_seed.json` — 5 risks across P2P, O2C, HCM, Basis.
Expand by adding entries; the engine ingests them on next restart.

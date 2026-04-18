# IntegriShield — Planning Roadmap

## Sprint Dev-4 Deliverables (current)

### Part A — Feature Deepening

| Item | Module | Status | Key files |
|------|--------|--------|-----------|
| A1 | m05 SAP MCP Suite — pluggable drivers | ✅ Complete | `m05/drivers/{mock,rfc,sql}.py`, `mcp_registry.py:620` |
| A2 | m06 Credential Vault — HashiCorp Vault backend | ✅ Complete | `m06/backends/{vault,memory}.py`, `services/__init__.py`, `vault.tf` |
| A3 | m13 SBOM Scanner — NVD 2.0 + OSV.dev live CVE feeds | ✅ Complete | `m13/feeds/{nvd,osv,cache}.py`, `dependency_extractor.py` |
| A4 | m14 Webhook Gateway — full fan-out dispatcher | ✅ Complete | `m14/services/{dispatcher,signer,retry}.py`, `m14/db.py`, `001_webhook_tables.sql` |
| A5 | Shared schemas: `cred_access.json`, `webhook_dlq.json` | ✅ Complete | `shared/schemas/v1/` |
| A5 | E2E test suite | ✅ Complete | `tests/e2e/` |

### Part B — Documentation

| Item | Status | Output |
|------|--------|--------|
| docs/STATUS_MATRIX.md | ✅ Complete | Module status table, stream catalog, sprint tracker |
| docs/README.md | ✅ Complete | Documentation index |
| Root README.md | ✅ Updated | Added module count + sprint badges |
| planning/README.md | ✅ This file | Live planning trail |
| IntegriShield_Dev4_StatusReport.docx | ✅ Complete | Exec report — 10-section Word doc with cover page, TOC, banded tables, KPI matrix |
| docs/Dev4_StatusReport.md | ✅ Complete | Markdown source of truth for report |

---

## Sprint Dev-5 Roadmap (planned)

### P1 — m16 MCP Security Layer (full JWT — partial work done in Dev-4)
- Dev-4 delivered: 10-rule RBAC engine, prompt-injection heuristics, rolling audit log, ALLOW/DENY/MODIFY decisions
- Remaining in Dev-5: JWT/OIDC caller identification (replace trusted role header), persistent Postgres audit log, per-tenant rate limiting
- Estimated: 2 days (reduced from 3–4 due to Dev-4 headstart)

### P2 — Full JWT auth across all modules
- Currently in `auth_poc_mode=True` passthrough
- Replace with real JWT validation using shared/auth/jwt_validator.py
- Estimated: 2 days

### P3 — OTel traces across all modules
- shared/telemetry/ already has OTel scaffold
- Wire span propagation: m01→m08→m12→m14
- Dashboard: per-request latency waterfall
- Estimated: 2 days

### P4 — Raise test coverage to 40% on deepened modules
- m05, m06, m13, m14 unit tests + integration tests in each module's tests/
- CI gate at 40% coverage
- Estimated: 3 days

---

## Sprint Dev-6 Roadmap (planned)

- Kubernetes production rollout (Helm charts exist — helm install + values tuning)
- AWS KMS-unsealed Vault (swap vault.tf dev-mode for HA cluster)
- Load testing: 1000 events/sec through full pipeline
- SLA targets: P99 < 200ms for MCP tool calls

---

## Known Gaps (explicit out-of-scope for Dev-4)

- m16 MCP Security Layer completion
- Frontend rewrite (dashboard stays as-is)
- Moving from POC auth passthrough to full JWT
- Kubernetes production rollout

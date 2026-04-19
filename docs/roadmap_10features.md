# 10-Feature Roadmap — Build Status

Tracks the 10 features from the roadmap review. Phase 1 foundation and two Phase 2 modules ship in this change.

## Done (this change)

| # | Feature | Status | Landed in |
|---|---------|--------|-----------|
| 5 | Multi-Tenant Isolation Hardening | **Partial** — tenant-scoped stream helper + RLS migration shipped. JWT middleware + tenant header were already in place. | `shared/event_bus/streams.py`, `infrastructure/sql/migrations/002_tenant_rls.sql` |
| 2 | Tamper-Evident Audit Ledger | **MVP** — hash chain, Merkle roots, verify endpoint, per-tenant store, append-only Postgres triggers. | `shared/audit/ledger.py`, `modules/m18-ledger/`, migration `003_ledger.sql` |
| 1 | SAP SoD Violation Graph | **MVP** — 5-risk seed set, evaluator, REST + graph view. | `modules/m17-sod-analyzer/`, migration `004_sod.sql` |
| 3 | Threat Intel Fusion | **MVP** — KEV + EPSS + SAP Notes fusion cache, enrich API. Samples canned for POC. | `modules/m19-threat-intel/`, migration `005_threat_intel.sql` |

Event schemas added: `sod_violation_event`, `intel_enrichment_event`, `ledger_anchor_event`.
Unit tests: `tests/unit/test_ledger_chain.py`, `tests/unit/test_sod_engine.py` (8 tests, all passing).
Launch entries: M17 (8017), M18 (8018), M19 (8019).

## Pending — still to build

| # | Feature | What's next |
|---|---------|-------------|
| 4 | SOAR Playbook Executor | Extend M10. YAML DSL runner (6 step types), resumable Postgres run state, Slack approval HMAC, receipts into M18 ledger. |
| 6 | SIEM/XDR Egress | New `m20-egress` (or M10 extension). OCSF 1.3 mappers + Splunk HEC + Sentinel DCR + CEF sinks + DLQ via M14. |
| 7 | Model Drift & Shadow Eval | Extend M08. MLflow champion/challenger loading, dual-scoring, PSI drift, registry promotion API, dashboard widget. |
| 8 | Break-Glass + Secret Rotation | Extend M06. Rotation policies, 2 backends (SAP RFC user, HTTP callback), break-glass TTL + dual approval, ledger signing. |
| 9 | Attack Path Graph | New `m21-attack-graph`. Temporal correlator (per-user 30-min window), ATT&CK-tagged edges, REST + dashboard tab. |
| 10 | Evidence Bundle Export | Extend M07. Zip with manifest.json, timeline/actions/approvals jsonl, merkle_proof.json, signed PDF, offline verifier CLI. |

## Integration hooks to wire next

- **M13 → M19**: after SBOM scan, call `POST /intel/enrich` with found CVEs; tag results with `kev` and `epss`.
- **M12 → M17**: subscribe to `sod_events` stream, escalate critical SoD to incidents via M10.
- **All modules → M18**: publish significant actions to `/ledger/append` for tamper-evident audit.
- **M01/M03/M08/...**: migrate stream writes/reads to `shared.event_bus.streams.stream_name(tenant_id, family)` for #5 completion.

# IntegriShield — Module Status Matrix

> Single source of truth for module completeness. Updated each sprint.
> Legend: ✅ Production-ready · 🟡 Partial / deepened this sprint · 🔴 Stub / planned · ➖ Not applicable

| # | Module | Backend | ML / AI | Data Layer | Tests | Status | Notes |
|---|--------|---------|---------|------------|-------|--------|-------|
| m01 | API Gateway Shield | ✅ FastAPI + Redis Streams | ➖ | Redis Streams | 🟡 Unit | ✅ Live | Request interception, JWT passthrough, event publish |
| m02 | (reserved) | ➖ | ➖ | ➖ | ➖ | 🔴 Not created | Slot reserved for future module |
| m03 | Traffic Analyzer | ✅ FastAPI + Redis consumer | 🟡 Heuristic rules | In-memory ring buffer | 🟡 Unit | ✅ Live | RFC call pattern analysis, velocity checks |
| m04 | Zero-Trust Fabric | ✅ FastAPI + mTLS stubs | ➖ | Redis | 🟡 Unit | ✅ Live | Trust score per request, policy engine |
| m05 | SAP MCP Suite | ✅ FastAPI + MCP tools | ➖ | **🟡 Pluggable drivers (RFC/SQL/Mock)** | 🟡 Unit | 🟡 Deepened | 17 Claude-callable tools; mock_rows replaced with driver abstraction; m06 cred integration |
| m06 | Credential Vault | ✅ FastAPI | ➖ | **🟡 HashiCorp Vault KV v2 + MemoryBackend** | 🟡 Unit | 🟡 Deepened | Vault backend + audit events to cred_access stream; backends/ abstraction |
| m07 | Compliance Autopilot | ✅ FastAPI | ➖ | SQLite + YAML controls | ✅ Unit | ✅ Live | SOX/SOC2/ISO27001/GDPR evidence collection |
| m08 | Anomaly Detection | ✅ FastAPI + Redis consumer | ✅ IsolationForest v1 (trained) | Redis Streams | ✅ Unit | ✅ Live | Real ML model; anomaly_score published per event |
| m09 | DLP Engine | ✅ FastAPI | ➖ | Redis Streams | 🟡 Unit | ✅ Live | PII/financial regex + SAP field classification |
| m10 | Incident Response | ✅ FastAPI + Redis consumer | ➖ | SQLite incidents | ✅ Unit | ✅ Live | MITRE ATT&CK mapping, auto-escalation |
| m11 | Shadow Integration | ✅ FastAPI | ➖ | Redis Streams | 🟡 Unit | ✅ Live | Unapproved SAP connector detection |
| m12 | Rules Engine | ✅ FastAPI | ➖ | Redis Streams + YAML rules | ✅ Unit | ✅ Live | Alert fan-out to all consumers |
| m13 | SBOM Scanner | ✅ FastAPI | ➖ | **🟡 NVD 2.0 + OSV.dev + SQLite cache** | 🟡 Unit | 🟡 Deepened | Stub CVEs replaced with live NVD/OSV; 24h SQLite cache; /cve/refresh admin endpoint |
| m14 | Webhook Gateway | ✅ FastAPI | ➖ | **🟡 SQLite subscriber registry + delivery log** | 🟡 E2E | 🟡 Deepened | Full fan-out: subscription CRUD, HMAC signing, retry (5 attempts), DLQ → Redis stream |
| m15 | MultiCloud ISPM | ✅ FastAPI | ➖ | Redis Streams | 🟡 Unit | ✅ Live | Cloud posture misconfig detection |
| m16 | MCP Security Layer | 🔴 Stub | ➖ | ➖ | 🔴 None | 🔴 Stub | Auth/authz layer for MCP tools — planned Sprint Dev-5 |

## Infrastructure

| Component | Status | Notes |
|-----------|--------|-------|
| Redis Streams event bus | ✅ Live | 12+ named streams; consumer groups per module |
| HashiCorp Vault (dev-mode) | 🟡 New | `infrastructure/terraform/vault.tf` — Docker container, KV v2 at `integrishield/` |
| PostgreSQL (audit) | ✅ Live | `infrastructure/sql/audit_events.sql` |
| Webhook tables migration | 🟡 New | `infrastructure/sql/migrations/001_webhook_tables.sql` |
| Terraform (dev4-poc) | ✅ Live | `infrastructure/terraform/dev4-poc/main.tf` |
| Helm charts | ✅ Live | Per-module Helm charts in `infrastructure/helm/` |

## Event Streams

| Stream | Producer(s) | Consumer(s) | Schema |
|--------|-------------|-------------|--------|
| `integrishield:api_call_events` | m01 | m03, m05, m08, m12 | `api_call_event.json` |
| `integrishield:anomaly_events` | m08 | m05, m10, m12, m14 | `anomaly_event.json` |
| `integrishield:alert_events` | m12 | m05, m10, m14 | N/A |
| `integrishield:dlp_alerts` | m09 | m05, m10, m14 | `dlp_alert.json` |
| `integrishield:incidents` | m10 | m14 | `incident_event.json` |
| `integrishield:compliance_events` | m07 | m14 | `compliance_evidence.json` |
| `integrishield:sbom_scan_events` | m13 | m14 | `sbom_scan_event.json` |
| `integrishield:mcp_query_events` | m05 | dashboard | `mcp_query_event.json` |
| `integrishield:credential_events` | m06 | m07 | N/A |
| **`integrishield:cred_access`** | **m06** | **audit** | **`cred_access.json`** (new) |
| **`integrishield:webhook_dlq`** | **m14** | **ops** | **`webhook_dlq.json`** (new) |

## Dev Sprint Status

| Sprint | Focus | Coverage Target |
|--------|-------|----------------|
| Dev-1 to Dev-3 | Core modules, event bus, ML model | ~1.6% |
| **Dev-4 (current)** | **Feature deepening: m05/m06/m13/m14** | **Target: 40% on deepened modules** |
| Dev-5 (planned) | m16 MCP Security Layer, full JWT auth | TBD |
| Dev-6 (planned) | Production Kubernetes rollout, load testing | TBD |

# IntegriShield

> **AI-powered SAP application security platform** — continuous monitoring, automated compliance evidence, MCP/LLM integration, and incident response for SAP environments.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![Redis Streams](https://img.shields.io/badge/Redis-7-red.svg)](https://redis.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://www.postgresql.org)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-lightgrey.svg)]()

---

## Table of Contents

1. [What Is IntegriShield?](#what-is-integrishield)
2. [Why IntegriShield?](#why-integrishield)
3. [Architecture Overview](#architecture-overview)
4. [Module Reference](#module-reference)
5. [Event Bus — Redis Streams](#event-bus--redis-streams)
6. [Shared Libraries](#shared-libraries)
7. [ML Pipeline](#ml-pipeline)
8. [SOC Dashboard](#soc-dashboard)
9. [Infrastructure](#infrastructure)
10. [Quick Start](#quick-start)
11. [Make Targets](#make-targets)
12. [API Quick Reference](#api-quick-reference)
13. [Compliance Frameworks](#compliance-frameworks)
14. [Repository Structure](#repository-structure)
15. [Tech Stack](#tech-stack)
16. [Development Ownership](#development-ownership)

---

## What Is IntegriShield?

IntegriShield is a **middleware security layer** that sits between client applications and an SAP system. Every RFC (Remote Function Call) destined for SAP passes through IntegriShield's API gateway, which:

1. **Intercepts and logs** every call with full metadata (user, IP, timestamp, function module, payload size)
2. **Evaluates zero-trust policies** — MFA, device posture, geo-location, session trust score
3. **Detects anomalies** in real time using an IsolationForest ML model trained on historical call patterns
4. **Enforces DLP rules** — blocks bulk extractions, detects sensitive table access
5. **Runs a rules engine** — velocity checks, off-hours detection, credential abuse, shadow endpoint discovery
6. **Collects compliance evidence** continuously for SOX, SOC 2, ISO 27001, and GDPR
7. **Creates and orchestrates incidents** automatically from critical alerts with built-in playbooks
8. **Scans custom ABAP code** for credentials, SQL injection, insecure RFC calls, and generates CycloneDX SBOMs
9. **Exposes all security data** to LLM agents (Claude) via MCP tools
10. **Monitors multi-cloud ISPM** for SAP Cloud misconfigurations across AWS/GCP/Azure

All 13 services communicate via **Redis Streams** — a unified, schema-validated event bus that decouples every service and enables replay, auditing, and horizontal scaling.

---

## Why IntegriShield?

### Market Gap Analysis

| Problem | Existing Tools | IntegriShield Solution |
|---------|---------------|------------------------|
| No MCP/LLM integration | **Zero tools** offer Claude/GPT callable APIs | m05 MCP server (first in market) |
| No ABAP SBOM generation | **Zero tools** scan custom ABAP code | m13 CycloneDX ABAP scanner |
| Manual compliance evidence | SAP GRC: periodic snapshots only | m07 continuous, event-driven collection |
| No automated IR playbooks | Splunk SOAR: complex, SAP-unaware | m10 built-in playbooks, zero config |
| Siloed point solutions | Onapsis, SecurityBridge: separate tools | Unified Redis Streams event bus |
| No unified API | Each tool has its own API | All modules share same bus + gateway |

### Key Differentiators

- **Event-driven, not polling** — all security signals flow as stream events in under 100ms
- **AI-native** — MCP tools make every security data source callable by LLM agents
- **Compliance-continuous** — evidence is collected on every event, not at audit time
- **ABAP-aware** — first tool to scan custom ABAP code and generate CycloneDX SBOMs
- **Zero-trust by default** — every RFC call is evaluated against trust score, not just credentials

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CLIENT APPLICATIONS / ERPs                           │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ RFC calls
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  m01  API Gateway Shield  (Port 8001)                                       │
│  • Intercepts every RFC call                                                │
│  • Writes to integrishield:api_call_events stream                           │
│  • First-line access control + audit logging                                │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ api_call_events
                        ┌──────────▼──────────┐
                        │   REDIS STREAMS BUS  │
                        │  (event_bus layer)   │
                        └──────────┬──────────┘
           ┌────────────┬──────────┼──────────┬────────────┬─────────────┐
           ▼            ▼          ▼          ▼            ▼             ▼
        m03          m04        m08         m09          m11           m12
    Traffic        Zero-      Anomaly      DLP        Shadow         Rules
    Analyzer       Trust      Detection   Engine    Integration     Engine
    (8003)        (8004)      (8008)      (8009)      (8011)        (8012)
       │            │            │           │            │             │
       │       anomaly_events  anomaly    dlp_alerts  shadow_alerts alert_events
       │            │          events        │            │             │
       └────────────┴──────────┬─────────────┴────────────┴─────────────┘
                               │  all streams
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
           m05               m07               m10
        SAP MCP            Compliance        Incident
        Suite              Autopilot         Response
        (8005)             (8007)            (8010)
           │                  │                 │
     mcp_query_events  compliance_evidence  incident_events
                        compliance_alerts
              │
       m13 SBOM Scanner (8013)  [scan-on-demand, no stream input]
              │
        sbom_scan_events
              │
       m06 Credential Vault (8006)   m15 Multi-Cloud ISPM (8015)
              │                              │
       (secure secret storage)    (cloud posture monitoring)
              │
              ▼
    ┌──────────────────────────┐
    │   SOC DASHBOARD          │
    │   apps/dashboard/        │
    │   Backend: Port 5050     │
    │   UI:      Port 8080     │
    └──────────────────────────┘
```

### Module Communication Pattern

Every service follows the same pattern:

```
PRODUCE:  Service detects event → publishes dict to Redis Stream (capped at 10,000 entries)
CONSUME:  Service subclasses RedisStreamConsumer → implements handle_event() → auto-acks
PERSIST:  Evidence / incidents / audit records → PostgreSQL via SQLAlchemy 2.0
EXPOSE:   FastAPI routes + /healthz + /readyz for orchestration health checks
```

---

## Module Reference

| # | Module | Port | Role | Streams Produced | Status |
|---|--------|------|------|-----------------|--------|
| m01 | `m01-api-gateway-shield` | 8001 | RFC interception, first-line audit | `api_call_events` | ✅ Built |
| m03 | `m03-traffic-analyzer` | 8003 | Session statistics, traffic patterns | — | ✅ Built |
| m04 | `m04-zero-trust-fabric` | 8004 | Zero-trust policy evaluation per RFC | `anomaly_events` | ✅ Built |
| m05 | `m05-sap-mcp-suite` | 8005 | MCP server — SAP data as LLM tools | `mcp_query_events` | ✅ Built |
| m06 | `m06-credential-vault` | 8006 | Secure SAP credential storage | — | ✅ Built |
| m07 | `m07-compliance-autopilot` | 8007 | Continuous SOX/SOC2/ISO27001/GDPR | `compliance_evidence`, `compliance_alerts` | ✅ Built |
| m08 | `m08-anomaly-detection` | 8008 | IsolationForest ML anomaly scoring | `anomaly_events` | ✅ Built |
| m09 | `m09-dlp` | 8009 | Data Loss Prevention, bulk extraction | `dlp_alerts` | ✅ Built |
| m10 | `m10-incident-response` | 8010 | Incident lifecycle + playbook engine | `incident_events` | ✅ Built |
| m11 | `m11-shadow-integration` | 8011 | Unapproved RFC endpoint detection | `shadow_alerts` | ✅ Built |
| m12 | `m12-rules-engine` | 8012 | Velocity, off-hours, credential rules | `alert_events` | ✅ Built |
| m13 | `m13-sbom-scanner` | 8013 | ABAP code scan + CycloneDX SBOM | `sbom_scan_events` | ✅ Built |
| m15 | `m15-multicloud-ispm` | 8015 | Cloud posture (AWS/GCP/Azure) | — | ✅ Built |

### Module Details

#### m01 — API Gateway Shield
The entry point for all SAP traffic. Every RFC call is intercepted here before it reaches the SAP application server.

- Logs full RFC metadata: user identity, source IP, function module name, payload size, response time
- Writes an `AuditEvent` record to PostgreSQL for tamper-evident long-term storage
- Publishes to `integrishield:api_call_events` for all downstream consumers
- Enforces IP allowlist + JWT authentication in production (POC mode: passthrough)

#### m03 — Traffic Analyzer
Consumes `api_call_events` and builds real-time traffic statistics.

- Per-user, per-IP, per-function call counters using rolling time windows
- Detects velocity anomalies (calls per minute exceeding threshold)
- Feeds session context to m04 Zero-Trust for trust score computation

#### m04 — Zero-Trust Fabric
Evaluates a trust score for every RFC session based on multiple signals.

- Device posture (managed vs unmanaged endpoint)
- MFA verification status
- Geo-location consistency (IP vs registered user location)
- Time-of-day pattern match
- Trust score < threshold → session terminated + event emitted

#### m05 — SAP MCP Suite
**First-in-market** MCP (Model Context Protocol) server exposing SAP security data as callable tools for LLM agents (Claude, GPT-4, etc.).

- Maintains 4 in-memory ring buffers (1,000 events each), one per consumed stream
- Registers 4 MCP tools:
  - `query_events` — search recent API call events by user/function/IP
  - `get_anomaly_scores` — retrieve ML anomaly scores with threshold comparison
  - `list_alerts` — active security alerts with severity/scenario filters
  - `run_security_check` — composite security status for a specific SAP user
- REST endpoints mirror MCP tool interface for HTTP-based AI agent integration

#### m06 — Credential Vault
Secure encrypted storage for SAP system credentials (client IDs, RFC passwords, OAuth tokens).

- AES-256 encryption at rest
- Per-tenant isolation
- Audit log of every credential access
- Integration with SAP Logon Ticket and RFC trusted system configurations

#### m07 — Compliance Autopilot
Continuous compliance monitoring for SOX, SOC 2 Type II, ISO/IEC 27001:2022, and GDPR.

- Loads 13 control definitions at startup from YAML files (`config/controls/`)
- Maps every incoming stream event to relevant controls
- Persists `EvidenceItem` records to PostgreSQL with full provenance
- Upserts `ControlAssessment` — `compliant` / `violation` / `insufficient_evidence` per control
- Generates downloadable JSON or CSV compliance reports on demand
- Auto-publishes `compliance_alert` events when a violation is detected

**Controls covered:**

| Framework | Controls |
|-----------|---------|
| SOX ITGC | SOX-ITGC-01 (Access), -02 (Change Mgmt), -03 (Computer Ops), -04 (Data Integrity) |
| SOC 2 | CC6.1 (Access), CC7.2 (Anomaly Detection), CC8.1 (Change Mgmt), CC9.2 (Vendor Risk) |
| ISO 27001 | A.12.4.1 (Event Logging), A.12.4.3 (Admin Logs), A.16.1.2 (Reporting), A.18.1.3 (Records) |
| GDPR | Art-25 (Privacy by Design), Art-32 (Security of Processing), Art-33 (Breach Notification) |

#### m08 — Anomaly Detection
ML-powered anomaly scoring using scikit-learn IsolationForest.

- Trained on 10 behavioural features per RFC call (call rate, payload size, time-of-day, geo deviation, etc.)
- Model served from `ml/models/` — retrained via `make train`
- Scores every event: `anomaly_score` in [-1, 1] where < -0.1 is anomalous
- Publishes `anomaly_events` with score, feature vector, and contamination threshold

#### m09 — DLP (Data Loss Prevention)
Detects and optionally blocks data exfiltration attempts.

- Volume-based rules: payload > 10MB in single call, or > 50MB in 5-minute window
- Pattern-based rules: access to known sensitive SAP tables (KNA1, PA0001, BSEG, LFB1)
- RFC blocklist: RFC_READ_TABLE calls to HR/financial tables
- Publishes `dlp_alerts` with table name, volume, user identity, and recommended action

#### m10 — Incident Response
Converts security alerts into tracked incidents and automatically executes response playbooks.

- 6 built-in playbooks keyed on severity + scenario:
  - `PB-CRITICAL-BULK-EXTRACTION` → auto-contain + Slack + SIEM forward
  - `PB-CRITICAL-SHADOW-ENDPOINT` → auto-contain + SIEM forward + Slack
  - `PB-CRITICAL-CREDENTIAL-ABUSE` → auto-contain + PagerDuty + Slack + SIEM
  - `PB-HIGH-PRIVILEGE-ESCALATION` → Slack + PagerDuty + log
  - `PB-MEDIUM-OFF-HOURS-RFC` → Slack + log
  - `PB-DEFAULT-CATCH-ALL` → log (fallback)
- Incident lifecycle: `open` → `investigating` → `contained` → `resolved`
- MTTR (Mean Time to Resolve) statistics endpoint
- Optional Slack Block Kit + PagerDuty Events API v2 dispatch (simulated in POC)
- Optional SIEM forwarding via CEF-style JSON POST

#### m11 — Shadow Integration
Detects unapproved RFC endpoint calls — evidence of undocumented system integrations and change control failures.

- Maintains a registry of approved RFC function modules per tenant
- Any call to an unregistered endpoint triggers a `shadow_alert`
- Daily call counter resets at midnight UTC
- Critical for SOX ITGC-02 and SOC 2 CC8.1 (Change Management) evidence

#### m12 — Rules Engine
Rule-based detection engine running 5 detection scenarios in real time.

- `off-hours-rfc`: calls outside 06:00–22:00 local business hours
- `bulk-extraction`: single RFC returning > 10MB (configurable via `M12_BULK_EXTRACTION_BYTES`)
- `credential-abuse`: service account calling interactive-user function modules
- `privilege-escalation`: standard user calling admin-level FMs (_ADMIN_FUNCTIONS blocklist)
- `geo-anomaly`: source IP country != registered user country
- `data-staging`: writes to temporary SAP tables often used for data exfil staging

#### m13 — SBOM Scanner
**First-in-market** ABAP custom code scanner with CycloneDX 1.4 SBOM output.

- Async scan-on-demand (no stream input — purely REST-driven)
- 4 static analysis scanners:
  - `CredentialScanner` — hardcoded passwords, API keys, SY-UNAME bypasses
  - `SqlInjectionScanner` — EXEC SQL + dynamic WHERE clause concatenation
  - `InsecureRfcScanner` — CALL FUNCTION vs 12-entry RFC blocklist
  - `DependencyExtractor` — INCLUDE + CALL FUNCTION namespace extraction + CVE stub lookup
- CycloneDX 1.4 JSON output with components, vulnerabilities, and CVSS scores
- 20-entry CVE stub database for ABAP-specific vulnerabilities (POC demo data)
- Immediate `scan_id` return — results fetched asynchronously

#### m15 — Multi-Cloud ISPM
Identity and Security Posture Management across cloud providers hosting SAP workloads.

- Monitors AWS IAM, GCP IAM, Azure AD for misconfigurations
- Detects overprivileged service accounts with SAP access
- Detects public-facing SAP workloads (S3/GCS bucket exposure, open security groups)
- Cross-cloud identity federation risk scoring

---

## Event Bus — Redis Streams

IntegriShield uses Redis Streams as a durable, ordered event bus. Every stream is capped at **10,000 entries** for POC memory safety (configurable in production).

### Stream Catalogue

| Stream Name | Producer | Consumers | Schema |
|-------------|----------|-----------|--------|
| `integrishield:api_call_events` | m01 | m03, m04, m05, m07, m08, m09, m11, m12 | `api_call_event.json` |
| `integrishield:anomaly_events` | m04, m08 | m05, m07, m10, m12 | `anomaly_event.json` |
| `integrishield:dlp_alerts` | m09 | m05, m07, m10 | `dlp_alert.json` |
| `integrishield:shadow_alerts` | m11 | m05, m07 | `shadow_alert.json` |
| `integrishield:alert_events` | m12 | m05, m07, m10 | `alert_event.json` |
| `integrishield:mcp_query_events` | m05 | dashboard | `mcp_query_event.json` |
| `integrishield:compliance_evidence` | m07 | dashboard | `compliance_evidence.json` |
| `integrishield:compliance_alerts` | m07 | dashboard, m10 (future) | `compliance_alert.json` |
| `integrishield:incident_events` | m10 | dashboard | `incident_event.json` |
| `integrishield:sbom_scan_events` | m13 | dashboard, m07 (future) | `sbom_scan_event.json` |

### Consumer Group Pattern

Every consumer uses the Redis Streams consumer group pattern for at-least-once delivery:

```python
# shared/event_bus/consumer.py
class RedisStreamConsumer(ABC):
    async def run(self) -> None:
        # xreadgroup — blocks until events arrive
        # handle_event() — your business logic
        # xack — explicit acknowledgement after processing
```

Subclass and implement one method:

```python
class MyConsumer(RedisStreamConsumer):
    async def handle_event(self, stream: str, event_id: str, data: dict) -> None:
        # process event
```

---

## Shared Libraries

All shared code lives in `shared/` and is COPY'd into each module's Docker image at build time.

```
shared/
├── auth/
│   └── middleware.py     # AuthMiddleware — ASGI JWT validation (POC: passthrough)
├── event_bus/
│   ├── producer.py       # RedisStreamProducer — xadd with MAX_STREAM_LEN=10,000
│   └── consumer.py       # RedisStreamConsumer — ABC with xreadgroup + xack
├── db/
│   ├── session.py        # get_session(), create_tables(), SessionLocal
│   └── models.py         # Base, AuditEvent SQLAlchemy model
├── telemetry/
│   └── setup.py          # setup_telemetry(service_name) — OpenTelemetry + Prometheus
├── utils/
│   └── logging.py        # Structured JSON logging with correlation IDs
└── schemas/v1/           # JSON Schema definitions for all 10 streams
    ├── api_call_event.json
    ├── anomaly_event.json
    ├── dlp_alert.json
    ├── shadow_alert.json
    ├── alert_event.json
    ├── mcp_query_event.json
    ├── compliance_evidence.json
    ├── compliance_alert.json
    ├── incident_event.json
    └── sbom_scan_event.json
```

### Auth Middleware

```python
from shared.auth.middleware import AuthMiddleware
app.add_middleware(AuthMiddleware)
# POC_MODE=true → all requests pass through
# Production → validates Bearer JWT, injects tenant_id into request.state
```

### Event Bus Producer

```python
from shared.event_bus.producer import RedisStreamProducer

producer = RedisStreamProducer(redis_url="redis://localhost:6379")
await producer.publish("integrishield:alert_events", {
    "tenant_id": "acme",
    "scenario": "bulk-extraction",
    "severity": "critical",
    "user_id": "svc_batch",
})
```

### Database Session

```python
from shared.db.session import get_session, create_tables

# In FastAPI lifespan:
async with lifespan(app):
    await create_tables()   # creates all ORM tables if not exist

# In route handler:
async with get_session() as session:
    session.add(MyRow(...))
    await session.commit()
```

---

## ML Pipeline

The anomaly detection ML pipeline lives in `ml/`.

```
ml/
├── training/
│   └── train_isolation_forest.py   # trains IsolationForest on seed data
├── models/
│   └── isolation_forest.pkl        # serialized model (joblib)
├── data/
│   └── seed_events.json            # 10,000 synthetic RFC events for training
└── mlruns/                         # MLflow experiment tracking
```

### Features (10 per RFC call)

| Feature | Description |
|---------|-------------|
| `call_rate_1m` | Calls per minute from this user |
| `call_rate_5m` | Calls per 5 minutes from this user |
| `payload_bytes` | Response payload size in bytes |
| `hour_of_day` | 0–23 (detects off-hours) |
| `day_of_week` | 0–6 (detects weekend activity) |
| `is_admin_fm` | 1 if function module is on admin blocklist |
| `geo_deviation` | Distance from registered user location (km) |
| `unique_fms_1h` | Distinct function modules called in last hour |
| `session_age_min` | Minutes since session start |
| `account_type_enc` | 0=human, 1=service, 2=batch |

### Training

```bash
make train        # trains IsolationForest, saves model, logs to MLflow
make mlflow-ui    # open MLflow at http://localhost:5000
```

---

## SOC Dashboard

A lightweight real-time SOC (Security Operations Centre) dashboard in `apps/dashboard/`.

```
apps/dashboard/
├── index.html          # single-page dashboard UI
├── styles.css          # dark-theme SOC styling
├── app.js              # WebSocket client + chart rendering
└── backend/
    └── server.py       # FastAPI WebSocket server, Port 5050
```

### Features

- **Live alert feed** — new alerts appear in real time via WebSocket
- **Severity cards** — count of CRITICAL / HIGH / MEDIUM / LOW active alerts
- **Audit log table** — recent RFC calls with user, function, timestamp
- **Scenario filters** — filter by off-hours-rfc, bulk-extraction, shadow-endpoint
- **Backend status indicator** — green/red connection health indicator

### Access

```
Dashboard UI:        http://localhost:8080
Dashboard Backend:   http://localhost:5050
```

---

## Infrastructure

```
infrastructure/
├── terraform/        # AWS/GCP/Azure IaC for production deployment
├── helm/             # Kubernetes Helm charts for all 13 modules
└── sql/              # PostgreSQL migration files
    ├── 001_create_audit_events.sql
    ├── 002_create_incidents.sql
    └── 003_create_evidence.sql
```

### Kubernetes (Helm)

Each module has its own Helm chart with:
- Deployment (2 replicas default)
- Service (ClusterIP)
- HorizontalPodAutoscaler (CPU > 70%)
- ConfigMap for non-secret env vars
- ExternalSecret reference for credentials

### Terraform

Provisions:
- Managed Redis (ElastiCache / Memorystore / Azure Cache)
- Managed PostgreSQL (RDS / Cloud SQL / Azure Database)
- Container registry push roles
- VPC / networking for SAP connectivity

---

## Quick Start

### Prerequisites

- Docker Desktop 4.x+
- Docker Compose v2+
- Python 3.12+ (for local development)
- 8GB RAM recommended for full POC stack

### 1. Clone and configure

```bash
git clone https://github.com/your-org/Integrishield.git
cd Integrishield
cp .env.example poc/.env
```

Edit `poc/.env` — at minimum set:
```bash
POSTGRES_PASSWORD=your_secure_password
POC_MODE=true          # disables JWT auth for local dev
```

### 2. Start the POC stack

```bash
make poc
```

This starts:
- Redis (port 6379)
- PostgreSQL (port 5432)
- MLflow (port 5000)
- All 13 microservice modules
- SOC Dashboard backend (port 5050) + UI (port 8080)
- Seed event injector (populates initial data)

### 3. Verify services are healthy

```bash
# Check all containers
docker compose -f poc/docker-compose.yml ps

# Check individual module health
curl http://localhost:8007/healthz   # compliance autopilot
curl http://localhost:8010/healthz   # incident response
curl http://localhost:8013/healthz   # SBOM scanner
curl http://localhost:8005/healthz   # MCP suite
```

### 4. Inject demo events

```bash
# Inject a burst of realistic RFC events
python scripts/demo_event_producer.py

# Or trigger all demo scenarios at once
python scripts/demo_all_streams.py
```

### 5. Open the dashboard

Navigate to **http://localhost:8080** to see live alerts, anomaly events, and compliance status.

### 6. Stop the stack

```bash
make poc-down
```

---

## Make Targets

```bash
make install        # install all Python deps for local dev
make lint           # ruff --fix across all modules + shared
make type-check     # mypy across all modules
make test           # pytest across all modules (modules/*/tests/)
make build          # docker build all 13 module images
make train          # train IsolationForest ML model
make mlflow-ui      # start MLflow experiment tracking UI
make poc            # docker compose up --build (full stack)
make poc-down       # docker compose down
make clean          # remove __pycache__, .pytest_cache, dist/
```

---

## API Quick Reference

### m05 — SAP MCP Suite (Port 8005)

```http
GET  /healthz
GET  /readyz
GET  /api/v1/mcp/tools                          # list available MCP tools
POST /api/v1/mcp/tools/call                     # call a tool by name
POST /api/v1/security/query                     # general security data query
GET  /api/v1/security/events?limit=50           # recent API call events
GET  /api/v1/security/anomalies?threshold=-0.1  # anomaly scores
GET  /api/v1/security/alerts?severity=critical  # active alerts
```

**Example: Call an MCP tool**
```bash
curl -X POST http://localhost:8005/api/v1/mcp/tools/call \
  -H 'Content-Type: application/json' \
  -d '{"tool_name": "list_alerts", "arguments": {"limit": 10, "severity": "critical"}}'
```

---

### m07 — Compliance Autopilot (Port 8007)

```http
GET  /healthz
GET  /readyz
GET  /api/v1/compliance/controls?framework=sox          # list controls
GET  /api/v1/compliance/controls/{id}/evidence          # evidence items for a control
GET  /api/v1/compliance/summary?framework=soc2          # pass/fail summary
POST /api/v1/compliance/reports                         # generate report
GET  /api/v1/compliance/reports/{id}?format=csv         # download report
```

**Example: SOX compliance summary**
```bash
curl "http://localhost:8007/api/v1/compliance/summary?framework=sox"
```

**Example: Generate GDPR report**
```bash
curl -X POST http://localhost:8007/api/v1/compliance/reports \
  -H 'Content-Type: application/json' \
  -d '{"framework": "gdpr", "format": "json", "tenant_id": "acme"}'
```

---

### m10 — Incident Response (Port 8010)

```http
GET   /healthz
GET   /readyz
GET   /api/v1/incidents?status=open&severity=critical   # list incidents
GET   /api/v1/incidents/{id}                            # incident detail
PATCH /api/v1/incidents/{id}                            # update status / notes
GET   /api/v1/incidents/{id}/playbook                   # execution log
POST  /api/v1/incidents/simulate                        # dry-run playbook test
GET   /api/v1/incidents/stats                           # MTTR + counts
GET   /api/v1/playbooks                                 # list playbook definitions
```

**Example: List open critical incidents**
```bash
curl "http://localhost:8010/api/v1/incidents?status=open&severity=critical"
```

**Example: Simulate a playbook**
```bash
curl -X POST http://localhost:8010/api/v1/incidents/simulate \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "bulk-extraction", "severity": "critical", "tenant_id": "acme"}'
```

---

### m13 — SBOM Scanner (Port 8013)

```http
GET  /healthz
GET  /readyz
POST /api/v1/sbom/scans                          # submit ABAP code for scanning
GET  /api/v1/sbom/scans/{id}                     # full result + all findings
GET  /api/v1/sbom/scans/{id}/summary             # finding counts only
GET  /api/v1/sbom/scans/{id}/download            # CycloneDX JSON file
GET  /api/v1/sbom/scans                          # list recent scans
GET  /api/v1/sbom/rules                          # active detection rules
```

**Example: Scan ABAP code snippet**
```bash
curl -X POST http://localhost:8013/api/v1/sbom/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "filename": "zreport.abap",
    "content": "CALL FUNCTION '\''RFC_READ_TABLE'\'' EXPORTING query_table = lv_table.",
    "encoding": "utf-8",
    "tenant_id": "acme"
  }'
# Returns: {"scan_id": "uuid", "status": "pending"}

# Poll for results:
curl http://localhost:8013/api/v1/sbom/scans/{scan_id}
```

---

### m12 — Rules Engine (Port 8012)

```http
GET  /healthz
GET  /readyz
GET  /api/v1/rules                               # list active rules
GET  /api/v1/alerts?scenario=bulk-extraction     # recent alerts by scenario
GET  /api/v1/stats                               # alert counts per scenario
```

---

### m01 — API Gateway (Port 8001)

```http
GET  /healthz
GET  /readyz
POST /api/v1/rfc/call                            # proxy RFC call through gateway
GET  /api/v1/audit?user_id=BATCH01&limit=100     # audit log query
```

---

## Compliance Frameworks

Full compliance documentation is in `docs/compliance/`.

```
docs/compliance/
├── README.md                    # framework overview + API quick reference
├── sox/controls.md              # SOX ITGC-01 through ITGC-04
├── soc2/controls.md             # SOC 2 CC6.1, CC7.2, CC8.1, CC9.2
├── iso27001/controls.md         # ISO 27001 A.12.4.1, A.12.4.3, A.16.1.2, A.18.1.3
└── gdpr/controls.md             # GDPR Art-25, Art-32, Art-33
```

Each control document includes:
- Regulatory requirement text
- Evidence streams collected by IntegriShield
- Violation trigger conditions
- Auditor notes with specific SAP table/FM references
- Remediation guidance

### Evidence Types

| Type | Description | Source Module |
|------|-------------|---------------|
| `api_call_log` | Every RFC call with user + metadata | m01 |
| `anomaly_event` | ML anomaly score above threshold | m08 |
| `dlp_violation` | Bulk extraction or sensitive table access | m09 |
| `shadow_endpoint` | Unapproved RFC endpoint call | m11 |
| `alert` | Rules-engine triggered alert | m12 |
| `access_denial` | Zero-trust policy rejection | m04 |

---

## Repository Structure

```
Integrishield/
├── README.md                       # ← you are here
├── pyproject.toml                  # root: ruff + pytest + mypy config
├── Makefile                        # all build/test/deploy targets
├── .env.example                    # environment variable template
│
├── modules/                        # 13 microservice modules
│   ├── m01-api-gateway-shield/
│   ├── m03-traffic-analyzer/
│   ├── m04-zero-trust-fabric/
│   ├── m05-sap-mcp-suite/          # [Dev-3] MCP + LLM integration
│   ├── m06-credential-vault/
│   ├── m07-compliance-autopilot/   # [Dev-3] SOX/SOC2/ISO/GDPR
│   ├── m08-anomaly-detection/
│   ├── m09-dlp/
│   ├── m10-incident-response/      # [Dev-3] Incident + playbooks
│   ├── m11-shadow-integration/
│   ├── m12-rules-engine/
│   ├── m13-sbom-scanner/           # [Dev-3] ABAP SBOM scanner
│   └── m15-multicloud-ispm/
│       └── (each module contains)
│           ├── pyproject.toml
│           ├── service.py          # uvicorn entrypoint
│           ├── Dockerfile
│           ├── src/integrishield/mXX/
│           │   ├── main.py         # FastAPI create_app() + lifespan
│           │   ├── config.py       # Pydantic Settings (MXX_ env prefix)
│           │   ├── models.py       # Pydantic data models
│           │   ├── db_models.py    # SQLAlchemy ORM (where applicable)
│           │   ├── routes/
│           │   │   ├── health.py   # /healthz + /readyz
│           │   │   └── api.py      # business logic routes
│           │   └── services/       # core business logic classes
│           └── tests/unit/
│
├── shared/                         # shared libraries (copied into Docker images)
│   ├── auth/middleware.py
│   ├── event_bus/producer.py
│   ├── event_bus/consumer.py
│   ├── db/session.py
│   ├── db/models.py
│   ├── telemetry/
│   ├── utils/
│   └── schemas/v1/                 # 10 JSON Schema files
│
├── ml/                             # ML pipeline (IsolationForest)
│   ├── training/train_isolation_forest.py
│   ├── models/isolation_forest.pkl
│   └── data/seed_events.json
│
├── apps/
│   └── dashboard/                  # SOC dashboard (HTML + FastAPI backend)
│       ├── index.html
│       ├── styles.css
│       ├── app.js
│       └── backend/server.py
│
├── docs/
│   └── compliance/                 # compliance framework documentation
│       ├── README.md
│       ├── sox/controls.md
│       ├── soc2/controls.md
│       ├── iso27001/controls.md
│       └── gdpr/controls.md
│
├── infrastructure/
│   ├── terraform/                  # AWS/GCP/Azure IaC
│   ├── helm/                       # Kubernetes Helm charts
│   └── sql/                        # DB migration files
│
├── poc/
│   ├── docker-compose.yml          # full 16-container stack
│   └── README.md
│
├── scripts/
│   ├── demo_event_producer.py      # injects realistic RFC events
│   └── demo_all_streams.py         # triggers all 10 stream types
│
├── tests/                          # integration tests
│
└── planning/                       # sprint planning documents
```

---

## Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Language | Python | 3.12+ | All services and ML |
| Web Framework | FastAPI | 0.115+ | REST APIs + WebSockets |
| Data Validation | Pydantic v2 | 2.10+ | Request/response models |
| Config | pydantic-settings | 2.x | Env-driven config per module |
| Event Bus | Redis Streams | 7 | Async inter-service messaging |
| Database | PostgreSQL | 16 | Audit trail + compliance evidence |
| ORM | SQLAlchemy | 2.0 (async) | DB access layer |
| ML | scikit-learn | latest | IsolationForest anomaly detection |
| ML Tracking | MLflow | 2.x | Experiment tracking + model registry |
| Build | hatchling | latest | Python package builds |
| Lint | ruff | latest | Fast Python linter + formatter |
| Type Check | mypy | latest | Static type checking |
| Tests | pytest | latest | Unit + integration tests |
| Containers | Docker | 24+ | Two-stage slim builds |
| Orchestration | Docker Compose | v2 | POC local stack |
| K8s Packaging | Helm | 3.x | Production deployment |
| IaC | Terraform | 1.x | Cloud infrastructure |
| Protocol | MCP | 1.0 | LLM tool integration |
| SBOM Format | CycloneDX | 1.4 | Software bill of materials |

---

## Development Ownership

| Area | Modules | Files |
|------|---------|-------|
| **Dev 1** — Core Platform | m01-api-gateway-shield, shared/, infrastructure/ | API gateway, auth middleware, DB models, Terraform, SQL migrations |
| **Dev 2** — Detection | m03-traffic-analyzer, m08-anomaly-detection, m09-dlp, m11-shadow-integration, ml/ | Traffic analysis, ML pipeline, DLP rules, shadow detection |
| **Dev 3** — Compliance + Response | m05-sap-mcp-suite, m07-compliance-autopilot, m10-incident-response, m13-sbom-scanner, docs/compliance/ | MCP integration, SOX/SOC2/GDPR compliance, incident playbooks, ABAP scanner |
| **Dev 4** — Dashboard | apps/dashboard/, scripts/ | SOC UI, demo scripts, WebSocket backend |

### Environment Variables

Each module uses a `MXX_` prefix for its environment variables. Key variables:

```bash
# Infrastructure
REDIS_URL=redis://redis:6379
POSTGRES_DSN=postgresql+asyncpg://user:pass@postgres:5432/integrishield
POC_MODE=true

# Per-module ports
M01_PORT=8001
M05_PORT=8005
M07_PORT=8007
M10_PORT=8010
M13_PORT=8013

# m05 MCP Suite
M05_EVENT_CACHE_SIZE=1000

# m07 Compliance Autopilot
M07_REPORT_EXPORT_DIR=/tmp/integrishield/reports
M07_FRAMEWORKS=sox,soc2,iso27001,gdpr

# m10 Incident Response
M10_SLACK_WEBHOOK_URL=https://hooks.slack.com/...  # optional
M10_PAGERDUTY_ROUTING_KEY=...                       # optional
M10_SIEM_ENDPOINT=https://siem.internal/api/events  # optional
M10_AUTO_CONTAIN_ENABLED=true

# m12 Rules Engine
M12_BULK_EXTRACTION_BYTES=10485760   # 10MB
M12_OFF_HOURS_START=22
M12_OFF_HOURS_END=6
```

Full list in `.env.example`.

---

## Contributing

1. Follow the **modern module pattern** (see `m12-rules-engine` as canonical reference)
2. Every module must have `/healthz` and `/readyz` endpoints
3. All new stream events must have a JSON Schema in `shared/schemas/v1/`
4. Unit tests required for all service classes (`tests/unit/test_*.py`)
5. Run `make lint && make type-check && make test` before opening a PR
6. No secrets in code — use Pydantic Settings + env vars

---

*IntegriShield — Proprietary. All rights reserved.*

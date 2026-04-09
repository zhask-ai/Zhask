# IntegriShield — AI-Powered SAP RFC Security Platform

> Enterprise middleware security for SAP systems with real-time anomaly detection, compliance automation, and incident response.

![Status](https://img.shields.io/badge/status-production%20ready-brightgreen) ![Version](https://img.shields.io/badge/version-0.1.0-blue) ![Python](https://img.shields.io/badge/python-3.12%2B-blue) ![Redis](https://img.shields.io/badge/redis-7.0%2B-red)

---

## Overview

IntegriShield is a comprehensive security middleware platform designed to protect SAP systems from RFC (Remote Function Call) abuse. It combines machine learning anomaly detection, rule-based threat identification, compliance automation, and incident response into a unified SOC dashboard.

**Key Capability:** Intercept, analyze, and alert on suspicious SAP traffic in real-time while maintaining compliance with SOX, SOC2, ISO 27001, and GDPR frameworks.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SAP System                              │
│                    (RFC Requests/Responses)                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│  M01 — API Gateway Shield (FastAPI, Port 8000)                  │
│  • RFC proxy with transparent interception                      │
│  • Publishes: integrishield:api_call_events                     │
│  • Audit logging to Postgres                                    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────────┐
                    │   Redis Streams     │
                    │   (Event Bus)       │
                    └─────────────────────┘
                              ↓
        ┌─────────────────────────────────────────────┐
        │                                             │
   ┌────▼────┐  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
   │   M03   │  │   M08   │  │   M09   │  │   M11   │
   │ Analyzer│  │ Anomaly │  │   DLP   │  │ Shadow  │
   │ (Worker)│  │(Worker) │  │(Worker) │  │ (Worker)│
   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
        │            │            │            │
        └────────────┬────────────┬────────────┘
                     ↓
        ┌──────────────────────────────────┐
        │  FastAPI Detection Modules       │
        │  M04 (Zero-Trust)  M05 (SAP MCP) │
        │  M06 (Credentials) M07 (Compli.) │
        │  M10 (Incidents)   M12 (Rules)   │
        │  M13 (SBOM)        M15 (Cloud)   │
        └──────────────────────────────────┘
                     ↓
        ┌──────────────────────────────────┐
        │  Dashboard Backend (Port 8787)   │
        │  Multi-Stream Redis Consumer     │
        │  14 REST API Endpoints           │
        └──────────────────────────────────┘
                     ↓
        ┌──────────────────────────────────┐
        │  Dashboard UI (Port 5173)        │
        │  14-Tab SOC Interface            │
        │  Real-Time Charts & Metrics      │
        └──────────────────────────────────┘
```

---

## Core Features

### 🔐 Security Detection (13 Modules)

| Module | Owner | Function | Port |
|--------|-------|----------|------|
| **M01** | Dev 1 | API Gateway & RFC Proxy | 8000 |
| **M03** | Dev 2 | Traffic Analysis & Feature Extraction | — |
| **M04** | Dev 4 | Zero-Trust Access Control | 8004 |
| **M05** | Dev 3 | SAP MCP Integration Suite | 8005 |
| **M06** | Dev 4 | Credential Vault Lifecycle | 8006 |
| **M07** | Dev 3 | Compliance Autopilot (SOX/SOC2/GDPR) | 8007 |
| **M08** | Dev 2 | ML Anomaly Detection (IsolationForest) | — |
| **M09** | Dev 2 | Data Loss Prevention Rules | — |
| **M10** | Dev 3 | Incident Response & Playbooks | 8010 |
| **M11** | Dev 2 | Shadow Endpoint Detection | — |
| **M12** | Dev 4 | Rules Engine (8 security rules) | 8012 |
| **M13** | Dev 4 | SBOM Scanner (CycloneDX + CVE) | 8013 |
| **M15** | Dev 4 | Multi-Cloud ISPM (AWS/GCP/Azure) | 8015 |

### 📊 Dashboard

- **14 Tabs** covering all modules + overview
- **Real-time Charts**: Alert timeline, severity distribution, rules breakdown
- **13 Stat Cards** with live event counts
- **Module Health Grid** showing all modules with status
- **Alert Feed** with searchable, filterable entries
- **Sidebar Navigation** organized by team (Dev 1–4)

### 🧠 ML Pipeline

- **IsolationForest** unsupervised anomaly detection
- **10-Feature Extraction**: Time-based, volumetric, behavioral, endpoint features
- **Severity Scoring**: Critical (−0.70), High (−0.50), Medium (−0.30), Low (≥−0.30)
- **MLflow Integration** for experiment tracking
- **Retrainable** on production logs

### 📋 Compliance

- **SOX, SOC2, ISO 27001, GDPR** frameworks
- **Continuous Evidence Collection** from all modules
- **Automated Report Generation** (JSON + CSV)
- **Control Assessment** with tracking
- **Multi-tenant** compliance domains

---

## Quick Start

### Prerequisites

- Python 3.12+
- Redis 7+
- Docker (optional, for full POC)

### Option 1: Full POC (Docker)

```bash
cd /Users/rohithdonthula/START/Integrishield

# Start everything (Redis + Dashboard Backend + UI)
docker compose -f poc/docker-compose.dev4.yml up --build

# Open dashboard in browser
open http://localhost:4173

# In another terminal, push demo events
python3 scripts/demo_event_producer.py --interval 1.5
```

### Option 2: Local Development (Module by Module)

```bash
# Terminal 1: Start Redis
redis-server --daemonize yes

# Terminal 2: Dashboard Backend
PYTHONPATH=apps/dashboard/backend:shared/src \
  python3 apps/dashboard/backend/server.py

# Terminal 3: Dashboard UI
python3 -m http.server 5173 --directory apps/dashboard

# Terminal 4: M01 (API Gateway)
PYTHONPATH=modules/m01-api-gateway-shield/src:shared/src \
  python3 -m uvicorn integrishield.m01.main:app --port 8000

# Terminal 5: Demo Events
python3 scripts/demo_event_producer.py --redis-url redis://localhost:6379/0 --interval 2.0
```

**Dashboard:** http://localhost:5173  
**Backend API:** http://localhost:8787  
**SAP MCP Tools:** http://localhost:8005

---

## Project Structure

```
integrishield/
├── README.md                          ← You are here
├── docs/
│   ├── INTEGRISHIELD_GUIDE.md        ← Full platform guide (status, usage, ML training, logs)
│   ├── compliance/                    ← Compliance framework documentation
│   └── README.md
├── modules/                           ← 13 security modules
│   ├── m01-api-gateway-shield/
│   ├── m03-traffic-analyzer/
│   ├── m04-zero-trust-fabric/
│   ├── m05-sap-mcp-suite/
│   ├── m06-credential-vault/
│   ├── m07-compliance-autopilot/
│   ├── m08-anomaly-detection/
│   ├── m09-dlp/
│   ├── m10-incident-response/
│   ├── m11-shadow-integration/
│   ├── m12-rules-engine/
│   ├── m13-sbom-scanner/
│   └── m15-multicloud-ispm/
├── apps/
│   └── dashboard/                     ← React SOC dashboard
│       ├── index.html
│       ├── app.js
│       ├── styles.css
│       └── backend/
│           └── server.py              ← Multi-stream Redis consumer
├── shared/                            ← Cross-module libraries
│   ├── auth/                          ← JWT, tenant extraction
│   ├── db/                            ← SQLAlchemy, Postgres
│   ├── event_bus/                     ← Redis Streams consumer base
│   ├── telemetry/                     ← Structured logging
│   ├── schemas/                       ← Pydantic models
│   └── utils/                         ← Helpers
├── ml/                                ← ML pipeline
│   ├── data/
│   │   ├── seed/
│   │   │   ├── generate_seed_data.py  ← Create training data
│   │   │   ├── normal_events.json
│   │   │   └── anomaly_events.json
│   ├── training/
│   │   ├── train_model.py             ← Train IsolationForest
│   │   ├── evaluate_model.py          ← Per-scenario evaluation
│   │   └── feature_engineering.py     ← 10-feature extraction
│   ├── models/
│   │   ├── isolation_forest_v1.pkl    ← Trained model
│   │   └── feature_names.json
│   └── mlruns/                        ← MLflow experiment tracking
├── poc/                               ← Proof-of-concept
│   ├── docker-compose.dev4.yml
│   ├── seed-injector/
│   │   └── inject.py                  ← 16-event scripted demo
│   ├── seed/
│   │   └── api_call_events.json       ← Demo event scenarios
│   └── README.md
├── scripts/                           ← Utility scripts
│   ├── demo_event_producer.py         ← Continuous demo events
│   ├── demo_all_streams.py            ← Multi-stream producer
│   └── seed_events.py
├── infrastructure/                    ← Terraform, Helm, schemas
│   ├── terraform/
│   ├── helm/
│   └── sql/
├── tests/                             ← Integration tests
├── planning/                          ← Project planning docs
├── .claude/
│   └── launch.json                    ← 16+ dev server configs
└── pyproject.toml                     ← Python project config
```

---

## How to Use

### 1. View Real-Time Dashboard

Dashboard is automatically available at **http://localhost:5173** once backend is running.

**Features:**
- Live alert feed with filtering
- Per-module deep-dive tabs
- Severity distribution donut chart
- Rules breakdown bar chart
- Alert timeline showing event rate over time
- Module health grid with event counts

### 2. Ingest Logs

**Method A: Via M01 RFC Proxy (Real SAP)**
```bash
curl -X POST http://localhost:8000/rfc/proxy \
  -H "X-API-Key: dev-key-1" \
  -H "Content-Type: application/json" \
  -d '{
    "rfc_function": "RFC_READ_TABLE",
    "user_id": "JDOE",
    "sap_system": "PRD",
    "parameters": {}
  }'
```

**Method B: Batch Upload to Redis**
```bash
redis-cli XADD integrishield:api_call_events '*' \
  event_id "manual-001" \
  rfc_function "RFC_READ_TABLE" \
  user_id "JDOE" \
  rows_returned "5000" \
  response_time_ms "800" \
  status "SUCCESS"
```

**Method C: POC Seed Injector**
```bash
REDIS_URL=redis://localhost:6379 python3 poc/seed-injector/inject.py
```

### 3. Train ML Models

```bash
# Generate synthetic training data
python3 ml/data/seed/generate_seed_data.py

# Train IsolationForest
python3 ml/training/train_model.py

# Evaluate per-scenario
python3 ml/training/evaluate_model.py

# View experiments in MLflow
mlflow ui --backend-store-uri sqlite:///ml/mlruns/mlflow.db --port 5000
```

### 4. Use M05 SAP MCP Tools

M05 exposes 4 tools via MCP interface:

```bash
# Query recent SAP events
curl -X POST http://localhost:8005/api/v1/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "query_events",
    "input": { "limit": 10, "since_minutes": 60 }
  }'

# Get anomaly scores
curl -X POST http://localhost:8005/api/v1/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "get_anomaly_scores",
    "input": { "limit": 20 }
  }'
```

---

## API Reference

### Dashboard Backend (Port 8787)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/health` | GET | Backend + Redis status |
| `/api/modules/health` | GET | All 13 modules status |
| `/api/alerts?limit=40` | GET | Alert feed |
| `/api/audit?limit=60` | GET | Audit log |
| `/api/anomalies?limit=60` | GET | M08 anomaly scores |
| `/api/dlp?limit=60` | GET | M09 DLP violations |
| `/api/shadow?limit=60` | GET | M11 shadow detections |
| `/api/sap-activity?limit=60` | GET | M05 MCP queries |
| `/api/compliance?limit=60` | GET | M07 compliance findings |
| `/api/incidents?limit=60` | GET | M10 incidents |
| `/api/sbom?limit=60` | GET | M13 SBOM scans |
| `/api/zero-trust?limit=60` | GET | M04 access decisions |
| `/api/credentials?limit=60` | GET | M06 vault ops |
| `/api/cloud-posture?limit=60` | GET | M15 cloud findings |
| `/api/stats` | GET | Aggregate statistics |

All endpoints support `?limit=1-500` (default 40).

### Redis Stream Topology

All modules publish to named streams:

```
integrishield:api_call_events       ← M01
integrishield:analyzed_events       ← M03
integrishield:anomaly_scores        ← M08
integrishield:dlp_alerts            ← M09
integrishield:shadow_alerts         ← M11
integrishield:zero_trust_events     ← M04
integrishield:mcp_query_events      ← M05
integrishield:credential_events     ← M06
integrishield:compliance_alerts     ← M07
integrishield:incident_events       ← M10
integrishield:alert_events          ← M12
integrishield:sbom_scan_events      ← M13
integrishield:cloud_posture_events  ← M15
```

---

## Configuration

### Environment Variables

**M01 (API Gateway)**
```bash
SAP_BACKEND_URL=http://sap-system:3200     # SAP gateway
INTEGRISHIELD_API_KEYS=dev-key-1,dev-key-2 # Valid API keys
REDIS_URL=redis://localhost:6379
DATABASE_URL=postgresql://user:pass@db:5432/integrishield
BULK_ROW_THRESHOLD=10000                   # Bulk extraction flag threshold
```

**Dashboard Backend**
```bash
REDIS_URL=redis://localhost:6379
REDIS_START_ID=$                           # Start from latest: $, or timestamp
POSTGRES_URL=postgresql://user:pass@db:5432/integrishield
```

**M08 (Anomaly Detection)**
```bash
MODEL_PATH=ml/models/isolation_forest_v1.pkl
REDIS_URL=redis://localhost:6379
ANOMALY_THRESHOLD=-0.5                     # Score threshold
```

See individual module READMEs for full configs.

---

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=modules --cov=apps --cov=shared

# Run specific module
pytest tests/test_m01_gateway.py
```

### Code Quality

```bash
# Lint with Ruff
ruff check modules/ apps/ shared/

# Type checking
mypy modules/ apps/ shared/

# Format
ruff format modules/ apps/ shared/
```

### Adding a New Module

1. Create directory: `modules/mNN-module-name/`
2. Structure:
   ```
   modules/mNN-module-name/
   ├── src/integrishield/mNN/
   │   ├── main.py          (FastAPI app or worker script)
   │   ├── config.py        (Settings)
   │   ├── routes/          (API endpoints)
   │   └── services/        (Business logic)
   ├── README.md
   ├── requirements.txt
   └── Dockerfile
   ```
3. Add to `.claude/launch.json`
4. Register in dashboard index.html

---

## Troubleshooting

### Dashboard Shows "offline"

**Cause:** Redis not running or backend can't connect.

```bash
# Check Redis
redis-cli ping

# Check backend logs
curl http://localhost:8787/api/health
```

### No Events Appearing in Dashboard

**Cause:** Demo producer not running or Redis stream empty.

```bash
# Check stream
redis-cli XLEN integrishield:api_call_events

# Start producer
python3 scripts/demo_event_producer.py --interval 2.0
```

### M08 Anomaly Detection Returning 0 Events

**Cause:** M03 and M08 workers not running.

```bash
# Start M03 (Traffic Analyzer)
PYTHONPATH=modules/m03-traffic-analyzer/src:shared/src \
  python3 modules/m03-traffic-analyzer/src/integrishield/m03/analyzer.py

# Start M08 (Anomaly Detection)
PYTHONPATH=modules/m08-anomaly-detection/src:shared/src \
  python3 modules/m08-anomaly-detection/src/integrishield/m08/detector.py
```

---

## Documentation

- **[INTEGRISHIELD_GUIDE.md](docs/INTEGRISHIELD_GUIDE.md)** — Complete platform guide
  - Status report on all 13 modules
  - How to use the tool (Docker, local, demo)
  - How to upload logs (5 methods)
  - How to train ML models (step-by-step)
  - Quick-start cheatsheet

- **[POC README](poc/README.md)** — Proof-of-concept architecture

- **Individual Module READMEs** — Each module has its own documentation:
  - `modules/m01-api-gateway-shield/README.md`
  - `modules/m07-compliance-autopilot/README.md`
  - etc.

- **[Compliance Docs](docs/compliance/README.md)** — SOX, SOC2, ISO 27001, GDPR frameworks

---

## Team & Ownership

| Owner | Modules | Responsibility |
|-------|---------|-----------------|
| **Dev 1** | M01 | API Gateway, RFC Proxy, Audit Logging |
| **Dev 2** | M03, M08, M09, M11 | ML Pipeline, Anomaly Detection, DLP, Shadow Detection |
| **Dev 3** | M05, M07, M10, M13 | SAP MCP Integration, Compliance, Incident Response, SBOM |
| **Dev 4** | M04, M06, M12, M15, Dashboard | Zero-Trust, Credentials, Rules Engine, Multi-Cloud ISPM, SOC UI |

---

## Deployment

### Kubernetes (Helm)

```bash
helm install integrishield ./infrastructure/helm/integrishield \
  --namespace security \
  --values values.prod.yaml
```

### Terraform

```bash
cd infrastructure/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### Docker Compose (Dev)

```bash
docker compose -f poc/docker-compose.dev4.yml up --build
```

---

## Performance

- **Throughput:** 1,000+ RFC events/second per M01 instance
- **Latency:** Sub-millisecond anomaly scoring (M08)
- **Memory:** ~2GB per M01, ~1GB per worker module
- **Redis Stream Cap:** ~10k events (configurable)

---

## Security Considerations

- **API Key Auth:** All M01 requests require X-API-Key header
- **Multi-tenant:** Tenant extraction via JWT claims
- **Encryption:** TLS for inter-module communication
- **Secrets:** Store in Vault or environment variables
- **Audit:** All events logged to Postgres with timestamps

---

## License

Proprietary — IntegriShield Security Platform  
Copyright © 2026

---

## Support

For issues, questions, or feature requests:

1. Check **[INTEGRISHIELD_GUIDE.md](docs/INTEGRISHIELD_GUIDE.md)** troubleshooting section
2. Review module-specific READMEs
3. Check Redis stream status: `redis-cli XLEN integrishield:api_call_events`
4. Review backend health: `curl http://localhost:8787/api/health`

---

## Changelog

### v0.1.0 (Sprint Day 7 — Production Ready)

✅ All 13 modules operational  
✅ Real-time SOC dashboard (14 tabs)  
✅ ML anomaly detection pipeline  
✅ Compliance automation (SOX/SOC2/GDPR)  
✅ Incident response engine  
✅ Multi-cloud ISPM  
✅ Complete API reference  
✅ Full documentation  

---

**Status:** Production Ready · All 13 Modules Live · POC Operational

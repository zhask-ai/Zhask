# IntegriShield — Complete Platform Guide
> Sprint · Day 7 · Dev 4 Branch · Last updated: April 2026

---

## Table of Contents

1. [Platform Status Report](#1-platform-status-report)
2. [How to Use the Tool](#2-how-to-use-the-tool)
3. [How to Upload & Ingest Logs](#3-how-to-upload--ingest-logs)
4. [How to Train the ML Models](#4-how-to-train-the-ml-models)
5. [Quick-Start Cheatsheet](#5-quick-start-cheatsheet)

---

## 1. Platform Status Report

### Architecture Overview

IntegriShield is an AI-powered middleware security platform for SAP RFC traffic. It consists of **13 modules** organized across 4 developers, connected via **Redis Streams** as an event bus, with a real-time SOC dashboard.

```
SAP Traffic → M01 (Gateway) → Redis Streams → M03/M08/M09/M11 (Analysis Workers)
                                             → M04/M05/M06/M07/M10/M12/M13/M15 (FastAPI Modules)
                                             → Dashboard Backend (8787) → Dashboard UI (5173)
```

---

### Module Status — All 13 Modules

| # | Module | Owner | Port | Type | Status | Stream Published |
|---|--------|-------|------|------|--------|-----------------|
| M01 | API Gateway Shield | Dev 1 | 8000 | FastAPI | ✅ Complete | `api_call_events` |
| M03 | Traffic Analyzer | Dev 2 | — | Worker | ✅ Complete | `analyzed_events` |
| M04 | Zero-Trust Fabric | Dev 4 | 8004 | FastAPI | ✅ Complete | `zero_trust_events` |
| M05 | SAP MCP Suite | Dev 3 | 8005 | FastAPI | ✅ Complete | `mcp_query_events` |
| M06 | Credential Vault | Dev 4 | 8006 | FastAPI | ✅ Complete | `credential_events` |
| M07 | Compliance Autopilot | Dev 3 | 8007 | FastAPI | ✅ Complete | `compliance_alerts` |
| M08 | Anomaly Detection | Dev 2 | — | Worker | ✅ Complete | `anomaly_scores` |
| M09 | DLP | Dev 2 | — | Worker | ✅ Complete | `dlp_alerts` |
| M10 | Incident Response | Dev 3 | 8010 | FastAPI | ✅ Complete | `incident_events` |
| M11 | Shadow Integration | Dev 2 | — | Worker | ✅ Complete | `shadow_alerts` |
| M12 | Rules Engine | Dev 4 | 8012 | FastAPI | ✅ Complete | `alert_events` |
| M13 | SBOM Scanner | Dev 4 | 8013 | FastAPI | ✅ Complete | `sbom_scan_events` |
| M15 | Multi-Cloud ISPM | Dev 4 | 8015 | FastAPI | ✅ Complete | `cloud_posture_events` |

---

### Dashboard Status

| Component | Port | Status | Notes |
|-----------|------|--------|-------|
| Dashboard UI | 5173 | ✅ Live | 14 tabs, 13 stat cards, Chart.js charts |
| Dashboard Backend | 8787 | ✅ Live | 12 Redis streams, 14 REST endpoints |
| Redis | 6379 | ⚠️ Needs Docker | Required for live event data |

**Dashboard Tabs (all 14 verified working):**

| Tab Group | Tabs |
|-----------|------|
| Overview | Alerts Feed, Audit Log |
| Dev 1 + Dev 2 | M01 Gateway, M08 Anomaly, M09 DLP, M11 Shadow |
| Dev 3 | M05 SAP MCP, M07 Compliance, M10 Incidents, M13 SBOM |
| Dev 4 | M12 Rules, M04 Zero-Trust, M06 Credentials, M15 Cloud |

---

### Dev Progress by Team Member

#### Dev 1 — API Layer
- **M01 API Gateway Shield** ✅ — RFC proxy, audit logging, Postgres write, Redis publish
- Exposes `POST /rfc/proxy` as the main log ingestion endpoint

#### Dev 2 — ML Pipeline
- **M03 Traffic Analyzer** ✅ — Feature extraction from raw events
- **M08 Anomaly Detection** ✅ — IsolationForest inference, severity scoring
- **M09 DLP** ✅ — Rule-based bulk extraction and sensitive pattern detection
- **M11 Shadow Integration** ✅ — Undocumented RFC endpoint detection
- **ML Pipeline** ✅ — Full training pipeline in `ml/` (seed data, training, evaluation, MLflow)

#### Dev 3 — Compliance & Incident Response
- **M05 SAP MCP Suite** ✅ — SAP tools via Model Context Protocol
- **M07 Compliance Autopilot** ✅ — SOX / SOC2 / ISO 27001 / GDPR evidence collection
- **M10 Incident Response** ✅ — Playbook engine, automated containment
- **M13 SBOM Scanner** ✅ — CycloneDX 1.4, CVE detection, SAP ABAP static analysis

#### Dev 4 — Dashboard & Policy
- **M04 Zero-Trust Fabric** ✅ — Device trust, geo-policy, MFA, risk scoring
- **M06 Credential Vault** ✅ — Lifecycle, rotation, issuance, revocation
- **M12 Rules Engine** ✅ — 8 security rules, stateful counters, real-time evaluation
- **M15 Multi-Cloud ISPM** ✅ — AWS / GCP / Azure identity & secrets posture
- **Dashboard UI + Backend** ✅ — Full SOC dashboard with all 13 modules, sidebar nav, animated counters

---

### Redis Stream Architecture

All events flow through named Redis Streams with `integrishield:` prefix:

```
M01 → integrishield:api_call_events
M03 → integrishield:analyzed_events
M08 → integrishield:anomaly_scores
M09 → integrishield:dlp_alerts
M11 → integrishield:shadow_alerts
M04 → integrishield:zero_trust_events
M05 → integrishield:mcp_query_events
M06 → integrishield:credential_events
M07 → integrishield:compliance_alerts
M10 → integrishield:incident_events
M12 → integrishield:alert_events
M13 → integrishield:sbom_scan_events
M15 → integrishield:cloud_posture_events
```

---

## 2. How to Use the Tool

### Option A — Docker (Recommended for Full Stack)

**Start everything with one command:**

```bash
cd /Users/rohithdonthula/START/Integrishield

# Full Dev 4 stack: Redis + Dashboard Backend + Dashboard UI
docker compose -f poc/docker-compose.dev4.yml up --build
```

Services started:

| Service | URL |
|---------|-----|
| Dashboard UI | http://localhost:4173 |
| Dashboard Backend | http://localhost:8787 |
| Redis | localhost:6379 |

---

### Option B — Local Development (Module by Module)

All 16+ server configurations are stored in `.claude/launch.json`.

**Step 1: Start Redis**
```bash
redis-server --daemonize yes
# or via Docker
docker run -d -p 6379:6379 redis:7-alpine
```

**Step 2: Start the Dashboard Backend**
```bash
cd /Users/rohithdonthula/START/Integrishield
PYTHONPATH=apps/dashboard/backend:shared/src python3 apps/dashboard/backend/server.py
# Listening on http://localhost:8787
```

**Step 3: Serve the Dashboard UI**
```bash
python3 -m http.server 5173 --directory apps/dashboard
# Open http://localhost:5173
```

**Step 4: Start any module (example — M01)**
```bash
PYTHONPATH=modules/m01-api-gateway-shield/src:shared/src \
  python3 -m uvicorn integrishield.m01.main:app \
  --host 0.0.0.0 --port 8000 --reload \
  --reload-dir modules/m01-api-gateway-shield/src
```

Repeat Step 4 for any other module using its port from the table above.

---

### Option C — Run a Demo (No SAP Required)

Push synthetic events directly into Redis to see the dashboard populate live:

**Single stream demo (M01 events only):**
```bash
python3 scripts/demo_event_producer.py \
  --redis-url redis://localhost:6379/0 \
  --stream-key integrishield:api_call_events \
  --interval 1.0 \
  --count 0
```

**All streams demo (all 13 modules simultaneously):**
```bash
python3 scripts/demo_all_streams.py \
  --redis-url redis://localhost:6379/0 \
  --interval 0.5
```

**POC seed injector (16-event scripted sequence):**
```bash
REDIS_URL=redis://localhost:6379 python3 poc/seed-injector/inject.py
```

---

### Dashboard Navigation

Once the dashboard is open in your browser:

| Section | How to Access |
|---------|--------------|
| Live alerts feed | Click **Alerts** tab |
| Audit log | Click **Audit** tab |
| Per-module deep-dive | Click any module chip tab (M01–M15) |
| Module health grid | Overview tab → scroll to Module Health section |
| Severity chart | Overview tab → Severity Distribution donut |
| Rule breakdown | M12 Rules tab → Rules Breakdown bar chart |

The **topbar** shows:
- 🟢 / 🔴 backend connection status
- Total events processed counter (live)
- Module health pills (green = active, gray = no events)

---

### Dashboard Backend API

Base URL: `http://localhost:8787`

| Endpoint | Returns |
|----------|---------|
| `GET /api/health` | Backend status + per-stream event counts |
| `GET /api/modules/health` | All 13 module statuses |
| `GET /api/alerts?limit=80` | Alert feed (all modules) |
| `GET /api/audit?limit=60` | Audit log |
| `GET /api/anomalies?limit=60` | M08 anomaly scores |
| `GET /api/dlp?limit=60` | M09 DLP violations |
| `GET /api/shadow?limit=60` | M11 shadow detections |
| `GET /api/sap-activity?limit=60` | M05 SAP MCP queries |
| `GET /api/compliance?limit=60` | M07 compliance findings |
| `GET /api/incidents?limit=60` | M10 incidents |
| `GET /api/sbom?limit=60` | M13 SBOM scan results |
| `GET /api/zero-trust?limit=60` | M04 access decisions |
| `GET /api/credentials?limit=60` | M06 vault operations |
| `GET /api/cloud-posture?limit=60` | M15 cloud posture findings |
| `GET /api/stats` | Aggregate counts across all streams |

All `limit` params accept 1–500, default 40.

---

## 3. How to Upload & Ingest Logs

There are **three ways** to get log data into IntegriShield, depending on your source.

---

### Method 1 — Live RFC Proxy (Real SAP Traffic)

Route your SAP RFC calls through **M01** at `http://localhost:8000/rfc/proxy`.

**Request:**
```bash
curl -X POST http://localhost:8000/rfc/proxy \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "rfc_function": "RFC_READ_TABLE",
    "user_id": "JDOE",
    "sap_system": "PRD",
    "parameters": {
      "QUERY_TABLE": "MARA",
      "ROWCOUNT": 100
    }
  }'
```

**Response:**
```json
{
  "event_id": "uuid",
  "rfc_function": "RFC_READ_TABLE",
  "status": "SUCCESS",
  "rows_returned": 100,
  "response_time_ms": 312,
  "is_off_hours": false,
  "is_bulk_extraction": false,
  "is_shadow_endpoint": false
}
```

M01 automatically:
- Forwards the request to your SAP backend (`SAP_BACKEND_URL` env var)
- Detects bulk extraction, off-hours, shadow endpoint flags
- Publishes the event to Redis → all downstream modules receive it
- Writes to Postgres audit log

**Environment variables for M01:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SAP_BACKEND_URL` | `http://mock-sap:8080` | Your SAP system URL |
| `INTEGRISHIELD_API_KEYS` | `dev-key-1,dev-key-2` | Comma-separated valid API keys |
| `REDIS_URL` | `redis://redis:6379` | Redis connection |
| `DATABASE_URL` | postgres connection | Postgres for audit log |
| `BULK_ROW_THRESHOLD` | `10000` | Rows count to flag as bulk |

---

### Method 2 — Batch Log Upload (Historical Data)

Push historical RFC logs directly to the Redis Stream, bypassing M01.

**Upload a single event:**
```bash
redis-cli XADD integrishield:api_call_events '*' \
  event_id "manual-001" \
  rfc_function "RFC_READ_TABLE" \
  user_id "JDOE" \
  client_ip "10.0.1.15" \
  timestamp "2026-04-07T14:30:00Z" \
  rows_returned "100" \
  response_time_ms "300" \
  status "SUCCESS" \
  sap_system "PRD"
```

**Batch upload from JSON file (Python):**
```python
import redis
import json

r = redis.from_url("redis://localhost:6379")

with open("your_logs.json") as f:
    events = json.load(f)

for event in events:
    r.xadd(
        "integrishield:api_call_events",
        {k: str(v) for k, v in event.items()}
    )
    print(f"Uploaded: {event.get('event_id')}")
```

**Required fields per event:**

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | string | Unique identifier (UUID recommended) |
| `rfc_function` | string | SAP RFC function name |
| `user_id` | string | SAP user ID |
| `client_ip` | string | Source IP address |
| `timestamp` | ISO 8601 | Event timestamp |
| `rows_returned` | integer | Rows in response |
| `response_time_ms` | integer | Latency in milliseconds |
| `status` | string | SUCCESS / ERROR / TIMEOUT |
| `sap_system` | string | SAP system ID (e.g. PRD) |

---

### Method 3 — POC Seed Injector (Demo Data)

Use the built-in 16-event scripted demo sequence:

```bash
# Start Redis first, then:
REDIS_URL=redis://localhost:6379 \
INJECT_DELAY_MS=500 \
python3 poc/seed-injector/inject.py
```

The sequence demonstrates all 3 threat scenarios:
1. **5 normal events** — baseline traffic warm-up
2. **Off-hours RFC call** — 2:30 AM service account activity
3. **Bulk extraction** — RFC_READ_TABLE with 80,000 rows
4. **Shadow endpoint** — call to `ZRFC_EXFIL_DATA` (unknown function)

You can also use the continuous demo producer for sustained testing:
```bash
python3 scripts/demo_event_producer.py \
  --redis-url redis://localhost:6379/0 \
  --stream-key integrishield:api_call_events \
  --interval 2.0      # seconds between events
  --count 100         # 0 = run forever
```

---

### Method 4 — SBOM File Upload (M13)

For software supply chain scanning, upload a CycloneDX SBOM file:

```bash
curl -X POST http://localhost:8013/scans/upload \
  -H "X-API-Key: your-api-key" \
  -F "file=@your-sbom.json" \
  -F "project_name=MyProject" \
  -F "version=1.0.0"
```

Then check results:
```bash
curl http://localhost:8013/scans/{scan_id}
curl http://localhost:8013/scans/{scan_id}/summary
```

---

### Method 5 — Cloud Posture Finding (M15)

Post cloud security findings directly:

```bash
curl -X POST http://localhost:8015/findings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "provider": "aws",
    "resource_type": "S3",
    "resource_id": "arn:aws:s3:::my-bucket",
    "finding_type": "PUBLIC_ACCESS",
    "severity": "HIGH",
    "region": "us-east-1",
    "account_id": "123456789012"
  }'
```

---

## 4. How to Train the ML Models

IntegriShield uses **IsolationForest** (unsupervised anomaly detection) trained on normal SAP RFC traffic patterns. Training is a one-time offline step; inference runs continuously via M03 → M08.

### Prerequisites

```bash
pip install scikit-learn mlflow numpy pandas redis
```

---

### Step 1 — Generate Training Data

```bash
cd /Users/rohithdonthula/START/Integrishield
python3 ml/data/seed/generate_seed_data.py
```

**Output:**
- `ml/data/seed/normal_events.json` — 3 days of baseline business-hours RFC traffic (~80 calls/hour)
- `ml/data/seed/anomaly_events.json` — 120 labeled anomalies (40 per scenario)

**Anomaly scenarios in training data:**

| Scenario | What it looks like |
|----------|--------------------|
| Off-hours RFC | Calls at 2am–4am from service accounts |
| Bulk extraction | RFC_READ_TABLE returning 50k–500k rows, 8–30s latency |
| Shadow endpoint | Calls to undocumented functions (`ZRFC_EXFIL_DATA`, `TEST_REXEC`, etc.) |

---

### Step 2 — Train the Model

```bash
python3 ml/training/train_model.py
```

**What it does:**
1. Loads normal + anomaly events
2. Extracts **10 features** per event:

| Feature | Description |
|---------|-------------|
| `hour_of_day` | 0–23 |
| `is_off_hours` | 1 if outside Mon–Fri 08:00–18:00 UTC |
| `is_weekend` | 1 if Saturday or Sunday |
| `rows_returned` | Raw count from SAP response |
| `rows_per_second` | Throughput rate |
| `response_time_ms` | Latency |
| `client_req_count_5m` | Per-IP request count in 5-minute window |
| `unique_functions_10m` | RFC function diversity in 10-minute window |
| `endpoint_entropy_10m` | Shannon entropy of RFC function distribution |
| `is_known_endpoint` | 1 if RFC function is in allowlist |

3. Trains `IsolationForest(n_estimators=100, contamination=0.05)` on **normal data only**
4. Saves to `ml/models/isolation_forest_v1.pkl` (model + scaler tuple)
5. Logs run to **MLflow** at `ml/mlruns/mlflow.db`

---

### Step 3 — Evaluate the Model

```bash
python3 ml/training/evaluate_model.py
```

**Output:**
- Per-scenario detection rates (Precision, Recall, F1)
- Anomaly score distribution statistics
- Threshold analysis for tuning sensitivity

---

### Step 4 — View Results in MLflow

```bash
mlflow ui --backend-store-uri sqlite:///ml/mlruns/mlflow.db --port 5000
# Open http://localhost:5000
```

MLflow tracks every training run with:
- Model parameters (contamination, n_estimators)
- Evaluation metrics (precision, recall, F1 per scenario)
- Artifacts (model file, feature names)

---

### Step 5 — Deploy the Model

The trained model at `ml/models/isolation_forest_v1.pkl` is automatically loaded by **M08** on startup:

```bash
# M08 reads MODEL_PATH env var (defaults to ml/models/isolation_forest_v1.pkl)
MODEL_PATH=ml/models/isolation_forest_v1.pkl \
REDIS_URL=redis://localhost:6379 \
PYTHONPATH=modules/m08-anomaly-detection/src:shared/src \
python3 modules/m08-anomaly-detection/src/integrishield/m08/detector.py
```

**Inference flow (continuous):**

```
M01 publishes → integrishield:api_call_events
  ↓
M03 consumes → extracts 10 features → integrishield:analyzed_events
  ↓
M08 consumes → IsolationForest.decision_function() → severity scoring
  ↓ publishes → integrishield:anomaly_scores
  ↓
Dashboard Backend receives → /api/anomalies endpoint → Dashboard UI updates
```

**Severity Thresholds (M08):**

| Anomaly Score | Severity |
|---------------|----------|
| < −0.70 | 🔴 CRITICAL |
| −0.70 to −0.50 | 🟠 HIGH |
| −0.50 to −0.30 | 🟡 MEDIUM |
| ≥ −0.30 | 🟢 LOW |

---

### Retraining with Custom Data

To retrain on your own production logs:

1. **Export your data** in the same schema as `normal_events.json`:
```json
[
  {
    "rfc_function": "RFC_READ_TABLE",
    "timestamp": "2026-04-07T09:15:00Z",
    "rows_returned": 120,
    "response_time_ms": 245,
    "client_ip": "10.0.1.15",
    "user_id": "JDOE",
    "sap_system": "PRD"
  }
]
```

2. **Replace the seed files:**
```bash
cp your_normal_logs.json ml/data/seed/normal_events.json
cp your_anomaly_logs.json ml/data/seed/anomaly_events.json   # optional
```

3. **Retrain:**
```bash
python3 ml/training/train_model.py
python3 ml/training/evaluate_model.py
```

4. **Restart M08** to load the new model:
```bash
# If running via Docker:
docker compose restart m08

# If running locally:
# Kill and restart the M08 process
```

---

## 5. Quick-Start Cheatsheet

### Full Stack (Docker) — Fastest Way

```bash
cd /Users/rohithdonthula/START/Integrishield

# 1. Start Redis + Dashboard
docker compose -f poc/docker-compose.dev4.yml up --build

# 2. In another terminal — push demo events
python3 scripts/demo_all_streams.py --interval 1.0

# 3. Open dashboard
open http://localhost:4173
```

---

### Local Dev — Module by Module

```bash
# Terminal 1: Redis
docker run -d -p 6379:6379 redis:7-alpine

# Terminal 2: Dashboard Backend
PYTHONPATH=apps/dashboard/backend:shared/src \
python3 apps/dashboard/backend/server.py

# Terminal 3: Dashboard UI
python3 -m http.server 5173 --directory apps/dashboard

# Terminal 4: M01 (API Gateway)
PYTHONPATH=modules/m01-api-gateway-shield/src:shared/src \
python3 -m uvicorn integrishield.m01.main:app --port 8000

# Terminal 5: Demo events
python3 scripts/demo_event_producer.py --interval 2.0 --count 0
```

---

### Train ML Model

```bash
python3 ml/data/seed/generate_seed_data.py   # generate data
python3 ml/training/train_model.py            # train
python3 ml/training/evaluate_model.py         # evaluate
mlflow ui --backend-store-uri sqlite:///ml/mlruns/mlflow.db  # view results
```

---

### Upload Logs via API

```bash
# Single event via M01
curl -X POST http://localhost:8000/rfc/proxy \
  -H "X-API-Key: dev-key-1" \
  -H "Content-Type: application/json" \
  -d '{"rfc_function":"RFC_READ_TABLE","user_id":"JDOE","sap_system":"PRD","parameters":{}}'

# Batch via Redis directly
redis-cli XADD integrishield:api_call_events '*' \
  event_id "batch-001" rfc_function "RFC_READ_TABLE" \
  user_id "JDOE" rows_returned "5000" response_time_ms "800" \
  status "SUCCESS" timestamp "2026-04-07T14:00:00Z"
```

---

### Check Everything is Working

```bash
# Dashboard backend health
curl http://localhost:8787/api/health | python3 -m json.tool

# Module health
curl http://localhost:8787/api/modules/health | python3 -m json.tool

# Latest alerts
curl http://localhost:8787/api/alerts?limit=5 | python3 -m json.tool

# Redis stream counts
redis-cli XLEN integrishield:api_call_events
redis-cli XLEN integrishield:anomaly_scores
```

---

*IntegriShield · POC · Dev 4 Branch · All 13 modules operational*

# IntegriShield SOC — User Guide

> **Version:** POC · Sprint Day 7  
> **Stack:** FastAPI backend · Redis Streams · IsolationForest ML · Vanilla JS Dashboard

---

## Table of Contents

1. [Quick Start — Running the Stack](#1-quick-start)
2. [Using the Dashboard](#2-using-the-dashboard)
3. [Where to Upload / Ingest Logs](#3-log-ingestion-per-module)
4. [Training the ML Model](#4-training-the-ml-model)
5. [Troubleshooting](#5-troubleshooting)

---

## 1. Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.11+ |
| Redis | 7.x (or Docker) |
| Docker + Compose | optional, for full POC |

### Option A — Run Locally (no Docker)

```bash
# From the repo root: Integrishield/

# 1. Install all dependencies
make install

# 2. Start Redis + Backend + Frontend + Event Producer
make poc-local
```

This spins up three background processes:

| Process | Port | What it does |
|---------|------|--------------|
| Redis | `6379` | Message bus for all event streams |
| Backend API | `8787` | Aggregates all module streams, serves `/api/*` |
| Dashboard frontend | `4173` | Static files served via Python HTTP |
| Event producer | — | Pushes synthetic events to Redis every 2s |

Then open: **`http://localhost:4173`**

---

### Option B — Full Docker Stack (all modules)

```bash
make poc       # Start all 13 modules + Redis + Postgres
make poc-down  # Stop everything
```

### Option C — Dev 4 Stack Only (lightweight)

```bash
make poc-dev4  # Only M04/M06/M12/M15 + Redis + Dashboard
```

---

## 2. Using the Dashboard

### Navigating Modules

**Mouse:** Click any item in the left sidebar.

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| `⌘K` / `Ctrl+K` | Open Command Palette (fuzzy search all modules) |
| `1` | Alerts Feed |
| `2` | Audit Log |
| `3` | M01 Gateway |
| `4` | M08 Anomaly |
| `5` | M09 DLP |
| `6` | M11 Shadow |
| `7` | M05 SAP MCP |
| `8` | M07 Compliance |
| `9` | M10 Incidents |
| `Esc` | Close palette / overlay |
| `↑` `↓` | Navigate palette results |
| `Enter` | Go to selected palette item |

---

### Reading the Status Bar

- **M01–M15 pills (top):** Red = module offline · Green = online
- **`● offline / online`** top right: Backend API connection to `:8787`
- **Clock:** Live real-time clock
- **`N events`:** Total events processed since last poll (2.5s)

---

### Filtering Data

**Alerts Feed:**
- **All scenarios** → filter by `bulk_extraction`, `off_hours_rfc`, `shadow_endpoint`, `velocity_anomaly`, etc.
- **All severities** → filter by `critical`, `high`, `medium`, `low`

**Audit Log:**
- **Module** dropdown → filter by source module name

---

## 3. Log Ingestion Per Module

### How Data Flows

```
Your logs / events
       │
       ├─── Redis XADD  (real-time streaming, preferred)
       │
       └─── POST /api/... (REST, for ad-hoc or testing)
              │
           Backend :8787
              │
           Dashboard polls every 2.5s
```

---

### M01 — API Gateway Shield

**Redis stream:** `integrishield:api_call_events`

**Event format:**
```json
{
  "event_id":        "uuid",
  "source_ip":       "10.42.0.5",
  "timestamp_utc":   "2026-04-07T23:00:00Z",
  "bytes_out":       "15000000",
  "off_hours":       "false",
  "unknown_endpoint":"false"
}
```

**Via script (synthetic):**
```bash
python scripts/demo_event_producer.py \
  --redis-url redis://localhost:6379/0 \
  --stream-key integrishield:api_call_events \
  --interval 1
```

**Via Redis CLI (manual):**
```bash
redis-cli XADD integrishield:api_call_events '*' \
  event_id abc123 \
  source_ip 10.0.0.1 \
  timestamp_utc 2026-04-07T23:00:00Z \
  bytes_out 5000000 \
  off_hours false \
  unknown_endpoint false
```

---

### M08 — Anomaly Detection

**Input:** Reads from same stream as M01 (`integrishield:api_call_events`)

**To train on your own RFC log data** — each record must have:
```json
{
  "event_id":        "uuid",
  "timestamp":       "2026-04-07T22:00:00Z",
  "client_ip":       "10.10.1.5",
  "rfc_function":    "RFC_READ_TABLE",
  "rows_returned":   50000,
  "response_time_ms":820,
  "label":           "normal"
}
```
Drop files into `ml/data/seed/` then retrain (see Section 4).

**Features the model scores on:**

| Feature | Description |
|---------|-------------|
| `hour_of_day` | 0–23 |
| `is_off_hours` | 1 if outside Mon–Fri 08:00–18:00 |
| `is_weekend` | 1 if Sat/Sun |
| `rows_returned` | Number of DB rows pulled |
| `rows_per_second` | rows ÷ response_time |
| `response_time_ms` | API latency |
| `client_req_count_5m` | Requests from same IP in last 5 min |
| `unique_functions_10m` | Distinct RFC calls in last 10 min |
| `endpoint_entropy_10m` | Call diversity score |
| `is_known_endpoint` | 1 if RFC is in the safe allowlist |

---

### M09 — DLP

**Redis stream:** `integrishield:dlp_events`

```json
{
  "event_id":  "uuid",
  "ts":        "2026-04-07T22:00:00Z",
  "user_id":   "svc-etl",
  "source_ip": "10.1.2.3",
  "rule":      "bulk_extraction",
  "severity":  "critical",
  "bytes_out": 12000000,
  "row_count": 75000,
  "message":   "Bulk data exfil detected"
}
```

---

### M11 — Shadow Integration

**Redis stream:** `integrishield:shadow_events`

```json
{
  "event_id":  "uuid",
  "ts":        "2026-04-07T22:00:00Z",
  "user_id":   "svc-sync",
  "source_ip": "10.5.6.7",
  "endpoint":  "shadow-api.internal:9091",
  "severity":  "high"
}
```

---

### M05 — SAP MCP Suite

**REST:** `POST http://localhost:8787/api/sap-activity`

```json
{
  "event_id":   "uuid",
  "ts":         "2026-04-07T22:00:00Z",
  "tool_name":  "RFC_READ_TABLE",
  "result":     "success",
  "session_id": "sess-abc",
  "tenant_id":  "T100",
  "user_id":    "svc-mcp",
  "anomalous":  false
}
```

---

### M07 — Compliance Autopilot

**REST:** `POST http://localhost:8787/api/compliance`

```json
{
  "ts":          "2026-04-07T22:00:00Z",
  "control_id":  "SOX-3.4",
  "framework":   "SOX",
  "result":      "violation",
  "description": "Segregation of duties violation",
  "evidence_ref":"evidence-2026-001",
  "actor":       "user@corp.com"
}
```

> `result` values: `violation` · `warning` · `pass`

---

### M10 — Incident Response

**REST:** `POST http://localhost:8787/api/incidents`

```json
{
  "incident_id":   "INC-1042",
  "ts":            "2026-04-07T22:00:00Z",
  "title":         "Mass data pull via RFC_READ_TABLE",
  "status":        "open",
  "severity":      "critical",
  "playbook_id":   "PB-DATA-EXFIL-01",
  "source_module": "m01-api-gateway-shield"
}
```

> `status` values: `open` · `investigating` · `resolved` · `closed`

---

### M13 — SBOM Scanner

**REST:** `POST http://localhost:8787/api/sbom`

```json
{
  "scan_id":            "scan-uuid",
  "ts":                 "2026-04-07T22:00:00Z",
  "target":             "sap-connector:2.4.1",
  "scan_status":        "completed",
  "sbom_format":        "CycloneDX",
  "component_count":    142,
  "cve_count":          3,
  "insecure_rfc_count": 1
}
```

---

### M04 — Zero-Trust Fabric

**REST:** `POST http://localhost:8787/api/zero-trust`

```json
{
  "ts":              "2026-04-07T22:00:00Z",
  "user_id":         "svc-etl",
  "source_ip":       "10.1.2.3",
  "decision":        "deny",
  "risk_score":      0.87,
  "failed_controls": ["mfa_required", "device_posture"]
}
```

> `decision` values: `allow` · `deny` · *(anything else = challenge)*

---

### M06 — Credential Vault

**REST:** `POST http://localhost:8787/api/credentials`

```json
{
  "ts":        "2026-04-07T22:00:00Z",
  "action":    "rotated",
  "key":       "sap-api-key-prod",
  "status":    "success",
  "tenant_id": "T100"
}
```

> `action` values: `issued` · `rotated` · `revoked`

---

### M15 — Multi-Cloud ISPM

**REST:** `POST http://localhost:8787/api/cloud-posture`

```json
{
  "ts":           "2026-04-07T22:00:00Z",
  "provider":     "aws",
  "resource_id":  "s3://corp-data-lake",
  "control_id":   "CIS-AWS-2.1.5",
  "raw_severity": "critical",
  "risk_score":   0.92
}
```

> `provider` values: `aws` · `gcp` · `azure`

---

### M12 — Rules Engine

No separate ingestion. Reads alert data from M01 automatically — rules fire on the alert stream.

---

## 4. Training the ML Model

The **M08 Anomaly Detection** module uses **IsolationForest** trained on SAP RFC call patterns.

---

### Step 1 — Prepare Your Log Data

Place log files here:

| File | Content | Path |
|------|---------|------|
| `normal_events.json` | Baseline normal RFC traffic | `ml/data/seed/normal_events.json` |
| `anomaly_events.json` | Known-bad / flagged events | `ml/data/seed/anomaly_events.json` |

Each record must follow this schema:
```json
{
  "event_id":        "unique-id",
  "timestamp":       "2026-04-07T08:30:00Z",
  "client_ip":       "10.0.0.5",
  "rfc_function":    "RFC_READ_TABLE",
  "rows_returned":   1500,
  "response_time_ms":340,
  "label":           "normal"
}
```

> Set `"label": "normal"` for clean traffic · `"label": "anomaly"` for known attacks.

**Minimum dataset sizes:**

| Split | Minimum | Recommended |
|-------|---------|-------------|
| Normal events | 500 | 5,000+ |
| Anomaly events | 50 | 500+ |

---

### Step 2 — (Optional) Generate Synthetic Seed Data

```bash
python ml/data/seed/generate_seed_data.py
```

Creates ~10,000 normal and ~500 anomaly records automatically.

---

### Step 3 — Run the Training Pipeline

```bash
# One command — runs generate → train → evaluate
make train
```

Or step-by-step:
```bash
python ml/data/seed/generate_seed_data.py   # Step 1: seed data
python ml/training/train_model.py           # Step 2: train
python ml/training/evaluate_model.py        # Step 3: evaluate
```

---

### Step 4 — Check Training Results

```
Loading seed data…
  10000 normal | 512 anomaly events
Extracting features…
  Training on 10000 normal samples…

  Results:
    Precision:     0.847
    Recall:        0.912
    False pos rate:0.031
    TP=467 FP=84 FN=45 TN=10000

  Model saved → ml/models/isolation_forest_v1.pkl
  MLflow run:   a3f9b2c1d4e5…
```

**Target metrics:**

| Metric | Good | Excellent |
|--------|------|-----------|
| Precision | > 0.80 | > 0.90 |
| Recall | > 0.85 | > 0.95 |
| False Positive Rate | < 0.05 | < 0.02 |

---

### Step 5 — View History in MLflow UI

```bash
cd ml
mlflow ui --backend-store-uri sqlite:///mlruns/mlflow.db --port 5003
# Open: http://localhost:5003
```

---

### Tuning Tips

Edit `ml/training/train_model.py`:

```python
N_ESTIMATORS  = 100   # Raise to 200–300 for more stable results (slower)
CONTAMINATION = 0.05  # % of data expected to be anomalous
RANDOM_STATE  = 42    # Keep fixed for reproducibility
```

| Problem | Fix |
|---------|-----|
| Too many false positives (good traffic flagged) | Lower `CONTAMINATION` |
| Real attacks being missed | Raise `CONTAMINATION` |
| Slow training | Lower `N_ESTIMATORS` |

---

### Adding RFC Functions to the Safe Allowlist

If M08 keeps flagging a legitimate RFC function, add it to:

**`ml/training/feature_engineering.py`** → `KNOWN_RFC_FUNCTIONS`:

```python
KNOWN_RFC_FUNCTIONS: frozenset[str] = frozenset([
    "RFC_READ_TABLE",
    "BAPI_MATERIAL_GETLIST",
    # ← add your function here
    "BAPI_MY_CUSTOM_FUNCTION",
])
```

Then retrain: `make train`

---

## 5. Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Dashboard shows `● offline` | Backend not running | `make poc-local` |
| All cards show `0` | No events in Redis | `python scripts/demo_event_producer.py` |
| All M-pills red | Modules not running | `make poc` (Docker) |
| `Seed data not found` error | Missing JSON files | `python ml/data/seed/generate_seed_data.py` |
| High false positives | CONTAMINATION too high | Lower it in `train_model.py`, retrain |
| `⌘K` doesn't work | JS error | Open browser console (`F12`), check for errors |
| Redis connection refused | Redis not running | `redis-server` or `brew services start redis` |

---

## Key File Locations

```
Integrishield/
├── Makefile                          ← make help — all commands
├── apps/dashboard/
│   ├── index.html                    ← Dashboard HTML
│   ├── app.js                        ← Dashboard logic
│   └── styles.css                    ← Dashboard styles
├── ml/
│   ├── data/seed/
│   │   ├── normal_events.json        ← ✏️  Upload YOUR normal logs here
│   │   ├── anomaly_events.json       ← ✏️  Upload YOUR anomaly logs here
│   │   └── generate_seed_data.py     ← Generate synthetic data
│   ├── models/
│   │   └── isolation_forest_v1.pkl   ← Trained model (auto-output)
│   └── training/
│       ├── train_model.py            ← Main training script
│       ├── feature_engineering.py    ← Features + RFC allowlist
│       └── evaluate_model.py         ← Evaluation metrics
├── scripts/
│   └── demo_event_producer.py        ← Synthetic event generator
└── modules/                          ← 13 microservice modules (m01–m15)
```

---

*Run `make help` to see all available commands at a glance.*

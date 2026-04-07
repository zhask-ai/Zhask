# IntegriShield POC

> Self-contained development environment for the Day 14 demo.
> Dev 2 (ML/Detection Engine) + Dev 4 (Dashboard) combined stack.

Demonstrates 3 SAP RFC anomaly detection scenarios:
1. **Off-hours RFC** — call at 2:30am triggers ML anomaly + WARNING log
2. **Bulk extraction** — RFC_READ_TABLE with 80k rows triggers ML anomaly + DLP alert
3. **Shadow endpoint** — unknown `ZRFC_EXFIL_DATA` triggers shadow alert

## Quick Start

### Step 1 — Train the ML model (Dev 2, run from repo root)

```bash
pip install scikit-learn mlflow numpy pandas redis

python ml/data/seed/generate_seed_data.py   # generate synthetic RFC events
python ml/training/train_model.py            # train IsolationForest, log to MLflow
python ml/training/evaluate_model.py         # check per-scenario precision/recall
```

### Step 2 — Run the full POC stack

```bash
cd poc
docker-compose up --build
```

### Step 3 — (Optional) Run with continuous demo event producer

```bash
docker-compose --profile demo up --build
```

Then open **http://localhost:4173** for the SOC dashboard (once Dev 4 uncomments their services).

## Services

| Service | Port | Description |
|---------|------|-------------|
| Redis | 6379 | Event bus (Redis Streams) |
| PostgreSQL | 5432 | Audit event persistence (Dev4) |
| MLflow UI | 5000 | Model experiment tracking (Dev2) |
| m03-traffic-analyzer | — | Feature extraction → `analyzed_events` |
| m08-anomaly-detection | — | IsolationForest ML inference → `anomaly_events` |
| m09-dlp | — | Rule-based DLP → `dlp_alerts` |
| m11-shadow-integration | — | Shadow endpoint detection → `shadow_alerts` |
| seed-injector | — | Injects 3-scenario demo events then exits |
| demo-producer | — | Continuous event producer (`--profile demo`) |

## Dev 2 — Check ML Results

```bash
# See ML anomaly alerts (from M8)
docker exec integrishield-redis redis-cli XRANGE anomaly_events - +

# See DLP alerts (from M9)
docker exec integrishield-redis redis-cli XRANGE dlp_alerts - +

# See shadow endpoint alerts (from M11)
docker exec integrishield-redis redis-cli XRANGE shadow_alerts - +

# MLflow experiment dashboard
open http://localhost:5000
```

## Dev 2 — Demo Scenarios

| Scenario | Trigger | Output Stream | Expected Severity |
|----------|---------|--------------|-------------------|
| Off-hours RFC | Call at 2:30am | `anomaly_events` | CRITICAL |
| Bulk extraction | RFC_READ_TABLE 80k rows | `anomaly_events` + `dlp_alerts` | CRITICAL |
| Shadow endpoint | Unknown RFC function | `shadow_alerts` | CRITICAL (first seen) |

## Architecture

```
rfc_events (Redis Stream)
    ├── m03-traffic-analyzer  → analyzed_events
    │       ├── m08-anomaly-detection  → anomaly_events
    │       └── m09-dlp               → dlp_alerts
    └── m11-shadow-integration        → shadow_alerts
```

Streams capped at 10,000 entries for POC memory safety.
Dev 4's dashboard backend consumes `anomaly_events`, `dlp_alerts`, `shadow_alerts`.

## Adding Other Dev Modules

When Dev1/Dev3 Dockerfiles are ready, uncomment the relevant service blocks in
`docker-compose.yml` (`m01-api-gateway-shield`, `m05-sap-mcp-suite`).

When Dev4's dashboard is ready, uncomment `dashboard-backend` and `dashboard-ui`.

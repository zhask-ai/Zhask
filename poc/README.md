# IntegriShield POC

> Self-contained development environment for the Day 14 demo.

## Dev 2 — ML Pipeline POC

Demonstrates 3 SAP RFC anomaly detection scenarios:
1. **Off-hours RFC** — call at 2:30am triggers ML anomaly + logs WARNING
2. **Bulk extraction** — RFC_READ_TABLE with 80k rows triggers ML anomaly + DLP alert
3. **Shadow endpoint** — unknown `ZRFC_EXFIL_DATA` triggers shadow alert

### Quick Start

#### Step 1 — Install Python deps and train the model

```bash
pip install scikit-learn mlflow numpy pandas redis

# Generate synthetic training data
python ml/data/seed/generate_seed_data.py

# Train IsolationForest (logs to ml/mlruns/)
python ml/training/train_model.py

# Evaluate per-scenario detection rates
python ml/training/evaluate_model.py
```

#### Step 2 — Run the Dev2 POC stack

```bash
cd poc
docker-compose up --build
```

Services started:
| Service | Port | Purpose |
|---------|------|---------|
| Redis | 6379 | Event streams |
| MLflow UI | 5000 | Model experiment tracking |
| m03-traffic-analyzer | — | Feature extraction |
| m08-anomaly-detection | — | ML inference |
| m09-dlp | — | Rule-based DLP |
| m11-shadow-integration | — | Shadow endpoint detection |
| seed-injector | — | Injects demo events (exits after) |

#### Step 3 — Check results

```bash
# See anomaly alerts (from M8)
docker exec poc-redis-1 redis-cli XRANGE anomaly_events - +

# See DLP alerts (from M9)
docker exec poc-redis-1 redis-cli XRANGE dlp_alerts - +

# See shadow alerts (from M11)
docker exec poc-redis-1 redis-cli XRANGE shadow_alerts - +

# MLflow experiment results
open http://localhost:5000
```

### Architecture

```
rfc_events (Redis Stream)
    ├── m03-traffic-analyzer  → analyzed_events
    │       ├── m08-anomaly-detection  → anomaly_events
    │       └── m09-dlp               → dlp_alerts
    └── m11-shadow-integration        → shadow_alerts
```

Streams are capped at 10,000 entries (approximate) for POC memory safety.

---

## Dev 4 — Dashboard + Infrastructure POC

### Quick Start

```bash
# From repo root — start the full stack (Redis, Postgres, Dashboard)
docker compose -f poc/docker-compose.dev4.yml up --build

# In another terminal — start the demo event producer
python scripts/demo_event_producer.py --interval 2
```

Then open **http://localhost:4173** to see the SOC dashboard.

| Service | Port | Description |
|---------|------|-------------|
| Redis | 6379 | Event bus (Redis Streams) |
| Dashboard Backend | 8787 | Multi-stream consumer + REST API |
| Dashboard UI | 4173 | SOC dashboard |

### Running Without Docker

```bash
# 1. Start Redis
redis-server --daemonize yes

# 2. Start backend
python3 apps/dashboard/backend/server.py

# 3. Start frontend
python3 -m http.server 4173 --directory apps/dashboard

# 4. Start demo event producer
python3 scripts/demo_event_producer.py --interval 2
```

### Seed Data

Pre-built SAP RFC events are in `poc/seed/api_call_events.json` covering all 3 scenarios:
- **Bulk extraction** — 15–22MB data transfers
- **Off-hours RFC** — 02:00–04:00 UTC service account calls
- **Shadow endpoint** — Undocumented RFC destinations

### Adding Other Dev Modules

When Dev1/Dev2/Dev3 have their Dockerfiles ready, uncomment the corresponding
service blocks in `docker-compose.yml` (M01, M05, M08) and restart.

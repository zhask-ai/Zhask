# IntegriShield — Dev 2 POC

Demonstrates 3 SAP RFC anomaly detection scenarios:
1. **Off-hours RFC** — call at 2:30am triggers ML anomaly + logs WARNING
2. **Bulk extraction** — RFC_READ_TABLE with 80k rows triggers ML anomaly + DLP alert
3. **Shadow endpoint** — unknown `ZRFC_EXFIL_DATA` triggers shadow alert

## Quick Start

### Step 1 — Install Python deps and train the model

```bash
pip install scikit-learn mlflow numpy pandas redis

# Generate synthetic training data
python ml/data/seed/generate_seed_data.py

# Train IsolationForest (logs to ml/mlruns/)
python ml/training/train_model.py

# Evaluate per-scenario detection rates
python ml/training/evaluate_model.py
```

### Step 2 — Run the full POC stack

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

### Step 3 — Check results

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

## Demo Checklist

- [ ] Off-hours RFC call → `anomaly_events` entry with `anomaly_type=OFF_HOURS`
- [ ] Bulk extraction → `anomaly_events` + `dlp_alerts` (rule=`HIGH_ROW_COUNT` or `BLOCKLISTED_FUNCTION`)
- [ ] Shadow endpoint → `shadow_alerts` with `first_seen=true`
- [ ] Alert latency < 5 seconds from Redis ingest to alert published

## Architecture

```
rfc_events (Redis Stream)
    ├── m03-traffic-analyzer  → analyzed_events
    │       ├── m08-anomaly-detection  → anomaly_events
    │       └── m09-dlp               → dlp_alerts
    └── m11-shadow-integration        → shadow_alerts
```

Streams are capped at 10,000 entries (approximate) for POC memory safety.
Dev 4's dashboard can consume all 4 streams directly.

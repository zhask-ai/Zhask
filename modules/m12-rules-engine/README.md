# M12 — Rules Engine

> Evaluates incoming API call events against detection rules for 3 POC scenarios.

## Scenarios

| Scenario | Trigger | Severity |
|----------|---------|----------|
| Bulk Extraction | `bytes_out > 10MB` | Critical |
| Off-Hours RFC | `off_hours == true` | Medium |
| Shadow Endpoint | `unknown_endpoint == true` | Critical |

## Running Locally

```bash
cd modules/m12-rules-engine
pip install -e ".[dev]"
uvicorn integrishield.m12.main:app --reload --port 8012
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe |
| GET | `/readyz` | Readiness probe |
| POST | `/api/v1/rules/evaluate` | Evaluate a single event |
| GET | `/api/v1/rules/alerts` | List recent alerts |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `M12_REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `M12_CONSUME_STREAM` | `integrishield:api_call_events` | Input stream to consume |
| `M12_PUBLISH_STREAM` | `integrishield:alert_events` | Output stream for alerts |
| `M12_BULK_EXTRACTION_BYTES` | `10000000` | Threshold for bulk extraction alert |

## Docker

```bash
docker build -t integrishield/m12-rules-engine:0.1.0 .
docker run -p 8012:8012 integrishield/m12-rules-engine:0.1.0
```

## Tests

```bash
pytest tests/unit -x --tb=short
```

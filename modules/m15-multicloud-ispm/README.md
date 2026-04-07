# M15 — Multi-Cloud ISPM

> Normalize and score cloud security findings across AWS, GCP, and Azure into a unified posture view.

## Risk Scoring

| Severity | Risk Score |
|----------|-----------|
| Critical | 90 |
| High | 75 |
| Medium | 50 |
| Low | 25 |

## Running Locally

```bash
cd modules/m15-multicloud-ispm
pip install -e ".[dev]"
uvicorn integrishield.m15.main:app --reload --port 8015
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe |
| POST | `/api/v1/cloud-posture/findings` | Ingest a cloud finding |
| GET | `/api/v1/cloud-posture/findings` | List recent findings |
| GET | `/api/v1/cloud-posture/summary` | Aggregate posture stats |

## Tests

```bash
pytest tests/unit -x --tb=short
```

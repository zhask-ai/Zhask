# M04 — Zero-Trust Fabric

> Continuous access evaluation with device trust, geo-policy, MFA verification, and session management.

## Decision Logic

| Condition | Risk Added | Control |
|-----------|-----------|---------|
| Untrusted device | +45 | `device_trust` |
| Geo-blocked region | +35 | `geo_policy` |
| MFA not verified | +20 | `mfa_required` |
| Session > 8 hours | +10 | `session_expired` |

- **risk ≥ 50** → DENY
- **0 < risk < 50** → CHALLENGE (step-up auth required)
- **risk = 0** → ALLOW

## Running Locally

```bash
cd modules/m04-zero-trust-fabric
pip install -e ".[dev]"
uvicorn integrishield.m04.main:app --reload --port 8004
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe |
| POST | `/api/v1/zero-trust/evaluate` | Evaluate access request |
| GET | `/api/v1/zero-trust/stats` | Policy evaluation statistics |

## Tests

```bash
pytest tests/unit -x --tb=short
```

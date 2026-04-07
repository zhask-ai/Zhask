# M06 — Credential Vault

> Secret storage, rotation lifecycle, and credential health monitoring for all IntegriShield modules.

## Features

- In-memory secret store (POC) — backed by HashiCorp Vault / AWS Secrets Manager in MVP
- Automated rotation urgency checks (OK → WARNING → CRITICAL)
- Secret lifecycle events published to Redis Streams

## Running Locally

```bash
cd modules/m06-credential-vault
pip install -e ".[dev]"
uvicorn integrishield.m06.main:app --reload --port 8006
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe |
| POST | `/api/v1/vault/secrets` | Create a new secret |
| POST | `/api/v1/vault/secrets/rotate` | Rotate an existing secret |
| GET | `/api/v1/vault/secrets` | List all secret metadata |
| GET | `/api/v1/vault/stats` | Vault health statistics |

## Tests

```bash
pytest tests/unit -x --tb=short
```

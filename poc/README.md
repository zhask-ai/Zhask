# IntegriShield POC

> Self-contained development environment for the Day 14 demo.

## Quick Start

```bash
# From repo root — start the full POC stack
docker compose -f poc/docker-compose.yml up --build

# In another terminal — start the demo event producer
docker compose -f poc/docker-compose.yml --profile demo up demo-producer
```

Then open **http://localhost:4173** to see the SOC dashboard.

## Services

| Service | Port | Description |
|---------|------|-------------|
| Redis | 6379 | Event bus (Redis Streams) |
| PostgreSQL | 5432 | Audit event persistence |
| Dashboard Backend | 8787 | Multi-stream consumer + REST API |
| Dashboard UI | 4173 | SOC dashboard (served by nginx) |
| Demo Producer | — | Generates events for all streams |

## Demo Event Producer

To exercise all dashboard panels with realistic data:

```bash
# Run locally (needs redis-py)
python scripts/demo_all_streams.py --interval 0.5

# Or via Docker (auto-starts with --profile demo)
docker compose -f poc/docker-compose.yml --profile demo up demo-producer
```

## Seed Data

Pre-built SAP RFC events are in `poc/seed/api_call_events.json` covering all 3 scenarios:
- **Bulk extraction** — 15–22MB data transfers
- **Off-hours RFC** — 02:00–04:00 UTC service account calls
- **Shadow endpoint** — Undocumented RFC destinations

## Adding Other Dev Modules

When Dev1/Dev2/Dev3 have their Dockerfiles ready, uncomment the corresponding
service blocks in `docker-compose.yml` (M01, M05, M08) and restart.

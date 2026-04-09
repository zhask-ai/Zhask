# Dev 4 Dashboard (POC)

SOC dashboard scaffold for the IntegriShield POC.

## What is included

- Live alert feed backed by a local API
- Alert severity summary cards
- Audit log table view
- Scenario filters for off-hours, bulk extraction, and shadow endpoint events
 - Backend status indicator

## Run locally

No build step is required.

1. Open a terminal and move to the repo root:

```bash
cd /Users/rohithdonthula/START/Integrishield
```

2. Install backend dependency:

```bash
python3 -m pip install redis
```

3. Start the dashboard backend (Redis stream mode):

```bash
export REDIS_URL="redis://localhost:6379/0"
export REDIS_STREAM_KEY="integrishield:api_call_events"
export REDIS_START_ID="$"
python3 apps/dashboard/backend/server.py
```

4. In a second terminal, serve the dashboard static files:

```bash
cd /Users/rohithdonthula/START/Integrishield/apps/dashboard
python3 -m http.server 4173
```

Then open `http://localhost:4173`.

## Publish a sample event to Redis

Use this to verify the pipeline quickly:

```bash
redis-cli XADD integrishield:api_call_events * event_id "e-1" bytes_out "12000000" off_hours "false" unknown_endpoint "false"
```

## One-command Docker stack (recommended)

From repo root:

```bash
cd /Users/rohithdonthula/START/Integrishield
docker compose -f poc/docker-compose.dev4.yml up --build
```

Then in another terminal publish a sample stream event:

```bash
docker exec -it integrishield-redis redis-cli XADD integrishield:api_call_events * event_id "e-1" bytes_out "12000000" off_hours "false" unknown_endpoint "false"
```

Verify:

```bash
curl -s http://localhost:8787/api/health
curl -s "http://localhost:8787/api/alerts?limit=5"
```

## Demo mode event generator

Use this script to continuously push realistic test events:

```bash
cd /Users/rohithdonthula/START/Integrishield
python3 scripts/demo_event_producer.py --interval 1.0
```

With Docker stack Redis:

```bash
python3 scripts/demo_event_producer.py --redis-url redis://localhost:6379/0 --stream-key integrishield:api_call_events
```

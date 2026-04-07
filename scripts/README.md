# Scripts

This directory contains utility scripts for Integrishield.

## Demo event producer

`demo_event_producer.py` publishes synthetic SAP-like events to the Redis stream consumed by the dashboard backend.

Example:

```bash
python3 scripts/demo_event_producer.py --redis-url redis://localhost:6379/0 --stream-key integrishield:api_call_events --interval 1.0
```

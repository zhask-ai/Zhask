"""Environment-driven configuration for M11."""
import os

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
INPUT_STREAM: str = os.getenv("INPUT_STREAM", "integrishield:api_call_events")
OUTPUT_STREAM: str = os.getenv("OUTPUT_STREAM", "integrishield:shadow_alerts")
CONSUMER_NAME: str = os.getenv("CONSUMER_NAME", "m11-shadow-integration")
GROUP_NAME: str = os.getenv("GROUP_NAME", "m11-consumers")
# Optional: path to a JSON file with known endpoints (overrides hardcoded list)
KNOWN_ENDPOINTS_FILE: str = os.getenv("KNOWN_ENDPOINTS_FILE", "")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

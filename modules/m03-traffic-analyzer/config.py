"""Environment-driven configuration for M03."""
import os

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
INPUT_STREAM: str = os.getenv("INPUT_STREAM", "integrishield:api_call_events")
OUTPUT_STREAM: str = os.getenv("OUTPUT_STREAM", "integrishield:traffic_flow_events")
CONSUMER_NAME: str = os.getenv("CONSUMER_NAME", "m03-traffic-analyzer")
GROUP_NAME: str = os.getenv("GROUP_NAME", "m03-consumers")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

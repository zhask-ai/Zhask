"""Environment-driven configuration for M03."""
import os

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
INPUT_STREAM: str = os.getenv("INPUT_STREAM", "rfc_events")
OUTPUT_STREAM: str = os.getenv("OUTPUT_STREAM", "analyzed_events")
CONSUMER_NAME: str = os.getenv("CONSUMER_NAME", "m03-traffic-analyzer")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

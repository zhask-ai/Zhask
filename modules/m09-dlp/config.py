"""Environment-driven configuration for M09."""
import os

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
INPUT_STREAM: str = os.getenv("INPUT_STREAM", "analyzed_events")
OUTPUT_STREAM: str = os.getenv("OUTPUT_STREAM", "dlp_alerts")
CONSUMER_NAME: str = os.getenv("CONSUMER_NAME", "m09-dlp")
GROUP_NAME: str = os.getenv("GROUP_NAME", "m09-consumers")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# DLP thresholds (overridable via env)
HIGH_ROW_COUNT_THRESHOLD: int = int(os.getenv("HIGH_ROW_COUNT_THRESHOLD", "10000"))
BLOCKLIST_ROW_THRESHOLD: int = int(os.getenv("BLOCKLIST_ROW_THRESHOLD", "5000"))
VELOCITY_THRESHOLD: int = int(os.getenv("VELOCITY_THRESHOLD", "50"))

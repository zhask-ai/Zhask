"""Environment-driven configuration for M08."""
import os

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
INPUT_STREAM: str = os.getenv("INPUT_STREAM", "integrishield:traffic_flow_events")
OUTPUT_STREAM: str = os.getenv("OUTPUT_STREAM", "integrishield:anomaly_scores")
CONSUMER_NAME: str = os.getenv("CONSUMER_NAME", "m08-anomaly-detection")
GROUP_NAME: str = os.getenv("GROUP_NAME", "m08-consumers")
MODEL_PATH: str = os.getenv("MODEL_PATH", "/app/ml/models/isolation_forest_v1.pkl")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

"""Pydantic Settings — env-driven configuration for M12 Rules Engine."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Module 12 configuration loaded from environment variables."""

    model_config = {"env_prefix": "M12_"}

    # --- service ---
    service_name: str = "m12-rules-engine"
    host: str = "0.0.0.0"
    port: int = 8012
    log_level: str = "info"

    # --- redis / event bus ---
    redis_url: str = "redis://localhost:6379/0"
    consume_stream: str = "integrishield:api_call_events"
    publish_stream: str = "integrishield:alert_events"
    consumer_group: str = "m12-rules-engine-cg"
    consumer_name: str = "m12-worker-1"

    # --- thresholds ---
    bulk_extraction_bytes: int = 10_000_000
    max_alerts_buffer: int = 500


settings = Settings()

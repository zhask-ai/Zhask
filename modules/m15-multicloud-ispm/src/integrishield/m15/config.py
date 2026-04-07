"""Pydantic Settings — env-driven configuration for M15 Multi-Cloud ISPM."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Module 15 configuration loaded from environment variables."""

    model_config = {"env_prefix": "M15_"}

    # --- service ---
    service_name: str = "m15-multicloud-ispm"
    host: str = "0.0.0.0"
    port: int = 8015
    log_level: str = "info"

    # --- redis / event bus ---
    redis_url: str = "redis://localhost:6379/0"
    publish_stream: str = "integrishield:cloud_posture_events"

    # --- supported providers ---
    supported_providers: str = "aws,gcp,azure"


settings = Settings()

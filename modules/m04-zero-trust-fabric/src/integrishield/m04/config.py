"""Pydantic Settings — env-driven configuration for M04 Zero-Trust Fabric."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Module 04 configuration loaded from environment variables."""

    model_config = {"env_prefix": "M04_"}

    # --- service ---
    service_name: str = "m04-zero-trust-fabric"
    host: str = "0.0.0.0"
    port: int = 8004
    log_level: str = "info"

    # --- redis / event bus ---
    redis_url: str = "redis://localhost:6379/0"
    publish_stream: str = "integrishield:zero_trust_events"

    # --- zero-trust policy ---
    device_trust_weight: int = 45
    geo_policy_weight: int = 35
    mfa_weight: int = 20
    risk_threshold_block: int = 50


settings = Settings()

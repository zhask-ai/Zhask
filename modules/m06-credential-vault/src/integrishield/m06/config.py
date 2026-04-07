"""Pydantic Settings — env-driven configuration for M06 Credential Vault."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Module 06 configuration loaded from environment variables."""

    model_config = {"env_prefix": "M06_"}

    # --- service ---
    service_name: str = "m06-credential-vault"
    host: str = "0.0.0.0"
    port: int = 8006
    log_level: str = "info"

    # --- redis / event bus ---
    redis_url: str = "redis://localhost:6379/0"
    publish_stream: str = "integrishield:credential_events"

    # --- vault policy ---
    max_secret_age_days: int = 30
    rotation_warning_days: int = 7
    encryption_algorithm: str = "AES-256-GCM"


settings = Settings()

"""Pydantic Settings — env-driven configuration for M07 Compliance Autopilot."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "M07_"}

    # --- service ---
    service_name: str = "m07-compliance-autopilot"
    host: str = "0.0.0.0"
    port: int = 8007
    log_level: str = "info"

    # --- redis / streams ---
    redis_url: str = "redis://localhost:6379/0"
    consume_streams: str = (
        "integrishield:api_call_events,"
        "integrishield:anomaly_events,"
        "integrishield:dlp_alerts,"
        "integrishield:shadow_alerts,"
        "integrishield:alert_events"
    )
    publish_evidence_stream: str = "integrishield:compliance_evidence"
    publish_alert_stream: str = "integrishield:compliance_alerts"
    consumer_group: str = "m07-compliance-autopilot-cg"
    consumer_name: str = "m07-worker-1"

    # --- database ---
    database_url: str = "postgresql://integrishield:integrishield_dev@localhost:5432/integrishield"

    # --- controls ---
    controls_config_path: str = "/app/config/controls"

    # --- reports ---
    report_retention_hours: int = 24


settings = Settings()

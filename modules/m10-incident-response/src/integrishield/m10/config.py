"""Pydantic Settings — env-driven configuration for M10 Incident Response."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "M10_"}

    # --- service ---
    service_name: str = "m10-incident-response"
    host: str = "0.0.0.0"
    port: int = 8010
    log_level: str = "info"

    # --- redis / streams ---
    redis_url: str = "redis://localhost:6379/0"
    consume_alert_stream: str = "integrishield:alert_events"
    consume_anomaly_stream: str = "integrishield:anomaly_events"
    consume_dlp_stream: str = "integrishield:dlp_alerts"
    publish_stream: str = "integrishield:incident_events"
    consumer_group: str = "m10-incident-response-cg"
    consumer_name: str = "m10-worker-1"

    # --- database ---
    database_url: str = "postgresql://integrishield:integrishield_dev@localhost:5432/integrishield"

    # --- incident rules ---
    auto_contain_severity: str = "critical"
    min_severity_for_incident: str = "medium"

    # --- notifications (empty = simulate) ---
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""
    siem_endpoint: str = ""


settings = Settings()

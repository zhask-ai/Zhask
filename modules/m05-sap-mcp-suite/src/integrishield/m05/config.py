"""Pydantic Settings — env-driven configuration for M05 SAP MCP Suite."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "M05_"}

    # --- service ---
    service_name: str = "m05-sap-mcp-suite"
    host: str = "0.0.0.0"
    port: int = 8005
    log_level: str = "info"

    # --- redis / event bus ---
    redis_url: str = "redis://localhost:6379/0"
    publish_stream: str = "integrishield:mcp_query_events"
    consume_streams: str = (
        "integrishield:api_call_events,"
        "integrishield:anomaly_events,"
        "integrishield:dlp_alerts,"
        "integrishield:alert_events"
    )
    consumer_group: str = "m05-mcp-suite-cg"
    consumer_name: str = "m05-worker-1"

    # --- cache ---
    event_cache_size: int = 1000

    # --- auth ---
    auth_poc_mode: bool = True

    # --- SAP data driver ---
    sap_driver: str = "mock"  # "mock" | "rfc" | "sql"
    m06_url: str = "http://localhost:8006"  # M06 Credential Vault URL
    sap_rfc_cred_key: str = "sap_rfc_creds"  # vault key for RFC credentials JSON
    sap_sql_cred_key: str = "sap_sql_creds"  # vault key for SQL credentials JSON


settings = Settings()

"""Pydantic Settings — env-driven configuration for M13 SBOM Scanner."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Module 13 configuration loaded from environment variables."""

    model_config = {"env_prefix": "M13_"}

    # --- service ---
    service_name: str = "m13-sbom-scanner"
    host: str = "0.0.0.0"
    port: int = 8013
    log_level: str = "info"

    # --- redis ---
    redis_url: str = "redis://localhost:6379/0"
    publish_stream: str = "integrishield:sbom_scan_events"

    # --- scan limits ---
    max_scan_size_bytes: int = 5_242_880  # 5 MB
    max_concurrent_scans: int = 10
    scan_store_max_size: int = 500

    # --- scanner config ---
    cve_stubs_path: str = "/app/config/cve_stubs.json"
    insecure_rfc_blocklist: str = (
        "RFC_READ_TABLE,BAPI_USER_CHANGE,BAPI_USER_CREATE,RFC_SYSTEM_INFO,"
        "TH_POPUP,SE16_READ,STRUST_MODIFY,SUSR_USER_AUTH_FOR_OBJ_GET,"
        "BAPI_USER_DELETE,RFC_ABAP_INSTALL_AND_RUN"
    )


settings = Settings()

"""Entrypoint for M05 SAP MCP Suite."""

import uvicorn

from integrishield.m05.config import settings
from integrishield.m05.main import app  # noqa: F401

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m05.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )

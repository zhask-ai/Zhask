"""Entrypoint for M10 Incident Response."""

import uvicorn

from integrishield.m10.config import settings
from integrishield.m10.main import app  # noqa: F401

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m10.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )

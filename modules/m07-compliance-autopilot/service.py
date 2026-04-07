"""Entrypoint for M07 Compliance Autopilot."""

import uvicorn

from integrishield.m07.config import settings
from integrishield.m07.main import app  # noqa: F401

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m07.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )

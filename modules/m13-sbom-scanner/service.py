"""Entrypoint for M13 SBOM Scanner."""

import uvicorn

from integrishield.m13.config import settings
from integrishield.m13.main import app  # noqa: F401

if __name__ == "__main__":
    uvicorn.run(
        "integrishield.m13.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )

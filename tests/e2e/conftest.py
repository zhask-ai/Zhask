"""E2E test fixtures — shared Redis and HTTP client setup."""

from __future__ import annotations

import os
import pytest

REDIS_URL = os.getenv("TEST_REDIS_URL", "redis://localhost:6379/0")
M06_URL   = os.getenv("TEST_M06_URL",   "http://localhost:8006")
M13_URL   = os.getenv("TEST_M13_URL",   "http://localhost:8013")
M14_URL   = os.getenv("TEST_M14_URL",   "http://localhost:8014")


@pytest.fixture(scope="session")
def redis_client():
    import redis  # noqa: PLC0415
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        r.ping()
    except Exception as exc:
        pytest.skip(f"Redis not available at {REDIS_URL}: {exc}")
    yield r


@pytest.fixture(scope="session")
def http():
    import httpx  # noqa: PLC0415
    with httpx.Client(timeout=10.0) as client:
        yield client

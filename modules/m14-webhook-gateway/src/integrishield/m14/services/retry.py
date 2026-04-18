"""Retry configuration and backoff for M14 Webhook Gateway."""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

MAX_ATTEMPTS = 5
BASE_DELAY = 2.0   # seconds
MAX_DELAY = 120.0  # seconds cap


def backoff_delay(attempt: int) -> float:
    """Exponential backoff: 2, 4, 8, 16, 32 seconds (capped at MAX_DELAY)."""
    return min(BASE_DELAY * (2 ** attempt), MAX_DELAY)


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    max_attempts: int = MAX_ATTEMPTS,
    label: str = "",
) -> tuple[T | None, int, str]:
    """
    Call fn() up to max_attempts times with exponential backoff.

    Returns (result, attempts_used, last_error).
    result is None on total failure.
    """
    last_error = ""
    for attempt in range(max_attempts):
        try:
            result = await fn()
            return result, attempt + 1, ""
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_attempts - 1:
                delay = backoff_delay(attempt)
                logger.warning(
                    "Attempt %d/%d failed for %s: %s — retrying in %.1fs",
                    attempt + 1, max_attempts, label, exc, delay,
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "All %d attempts failed for %s: %s", max_attempts, label, exc
                )
    return None, max_attempts, last_error

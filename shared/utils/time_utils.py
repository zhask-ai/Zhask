"""
shared.utils.time_utils
-----------------------
Time helpers for IntegriShield modules.

Key function: is_off_hours()
  Drives the "off-hours RFC call" detection scenario in M01.
  Business hours = 06:00–22:00 UTC (covers most SAP customer time zones).
  Any call outside that window is flagged as off-hours.

Owned by Dev 1.
"""

from datetime import datetime, timezone

# Business hours window (UTC).  Adjust at config level post-POC.
BUSINESS_HOUR_START = 6   # 06:00 UTC
BUSINESS_HOUR_END   = 22  # 22:00 UTC  (exclusive)


def utc_now() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(tz=timezone.utc)


def hour_of_day(dt: datetime | None = None) -> int:
    """Return the UTC hour (0-23) for *dt*, defaulting to now."""
    if dt is None:
        dt = utc_now()
    # Normalise to UTC so callers can pass any tz-aware datetime.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.hour


def is_off_hours(
    dt: datetime | None = None,
    start: int = BUSINESS_HOUR_START,
    end: int = BUSINESS_HOUR_END,
) -> bool:
    """
    Return True when *dt* falls outside [start, end) UTC hours.

    Examples
    --------
    >>> is_off_hours(datetime(2026, 4, 7, 2, 0, tzinfo=timezone.utc))   # 02:00 UTC
    True
    >>> is_off_hours(datetime(2026, 4, 7, 14, 0, tzinfo=timezone.utc))  # 14:00 UTC
    False
    """
    hour = hour_of_day(dt)
    return hour < start or hour >= end


def iso_now() -> str:
    """Return the current UTC time as an ISO-8601 string (for event payloads)."""
    return utc_now().isoformat().replace("+00:00", "Z")

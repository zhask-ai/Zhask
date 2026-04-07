"""Unit tests for feature extraction functions (m03 / feature_engineering)."""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from ml.training.feature_engineering import (
    hour_of_day,
    is_known_endpoint,
    is_off_hours,
    is_weekend,
    parse_timestamp,
    rows_per_second,
)


class TestTimestampParsing:
    def test_parse_z_suffix(self):
        ts = parse_timestamp("2026-04-07T14:23:45Z")
        assert ts.hour == 14
        assert ts.minute == 23

    def test_parse_utc_offset(self):
        ts = parse_timestamp("2026-04-07T14:23:45+00:00")
        assert ts.hour == 14


class TestOffHours:
    def test_business_hours_weekday(self):
        # Tuesday 10am UTC
        ts = datetime(2026, 4, 7, 10, 0, 0, tzinfo=timezone.utc)
        assert is_off_hours(ts) == 0

    def test_before_8am_weekday(self):
        ts = datetime(2026, 4, 7, 7, 59, 0, tzinfo=timezone.utc)
        assert is_off_hours(ts) == 1

    def test_after_6pm_weekday(self):
        ts = datetime(2026, 4, 7, 18, 0, 0, tzinfo=timezone.utc)
        assert is_off_hours(ts) == 1

    def test_saturday(self):
        # 2026-04-11 is a Saturday
        ts = datetime(2026, 4, 11, 10, 0, 0, tzinfo=timezone.utc)
        assert is_off_hours(ts) == 1

    def test_2am(self):
        ts = datetime(2026, 4, 7, 2, 30, 0, tzinfo=timezone.utc)
        assert is_off_hours(ts) == 1


class TestIsWeekend:
    def test_monday(self):
        ts = datetime(2026, 4, 6, 10, 0, 0, tzinfo=timezone.utc)
        assert is_weekend(ts) == 0

    def test_sunday(self):
        ts = datetime(2026, 4, 12, 10, 0, 0, tzinfo=timezone.utc)
        assert is_weekend(ts) == 1


class TestRowsPerSecond:
    def test_basic(self):
        assert rows_per_second(1000, 500) == pytest.approx(2000.0)

    def test_zero_rows(self):
        assert rows_per_second(0, 300) == pytest.approx(0.0)

    def test_zero_response_time_safe(self):
        # response_time_ms=0 should not divide by zero (clamped to 1ms)
        result = rows_per_second(100, 0)
        assert result > 0


class TestKnownEndpoint:
    def test_known(self):
        assert is_known_endpoint("RFC_PING") == 1
        assert is_known_endpoint("RFC_READ_TABLE") == 1

    def test_unknown(self):
        assert is_known_endpoint("ZRFC_EXFIL_DATA") == 0
        assert is_known_endpoint("UNKNOWN_FUNC") == 0

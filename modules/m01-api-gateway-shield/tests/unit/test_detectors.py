"""
Unit tests for M01 detectors.
No Redis, no Postgres, no SAP — pure logic only.
"""

import pytest
from datetime import datetime, timezone

from integrishield.m01.services.detectors import (
    detect_off_hours,
    detect_bulk_extraction,
    detect_shadow_endpoint,
    run_detectors,
    _BULK_ROW_THRESHOLD,
)


# ── detect_off_hours ──────────────────────────────────────────────────────────

class TestOffHours:
    def test_2am_utc_is_off_hours(self):
        dt = datetime(2026, 4, 7, 2, 0, tzinfo=timezone.utc)
        assert detect_off_hours(dt) is True

    def test_midnight_utc_is_off_hours(self):
        dt = datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc)
        assert detect_off_hours(dt) is True

    def test_business_hours_is_not_off_hours(self):
        dt = datetime(2026, 4, 7, 14, 0, tzinfo=timezone.utc)
        assert detect_off_hours(dt) is False

    def test_exactly_on_start_boundary_is_not_off_hours(self):
        # 06:00 UTC is the first business hour
        dt = datetime(2026, 4, 7, 6, 0, tzinfo=timezone.utc)
        assert detect_off_hours(dt) is False

    def test_exactly_on_end_boundary_is_off_hours(self):
        # 22:00 UTC is the first off-hours moment
        dt = datetime(2026, 4, 7, 22, 0, tzinfo=timezone.utc)
        assert detect_off_hours(dt) is True


# ── detect_bulk_extraction ───────────────────────────────────────────────────

class TestBulkExtraction:
    def test_above_threshold_is_bulk(self):
        assert detect_bulk_extraction(_BULK_ROW_THRESHOLD + 1) is True

    def test_at_threshold_is_not_bulk(self):
        assert detect_bulk_extraction(_BULK_ROW_THRESHOLD) is False

    def test_zero_rows_is_not_bulk(self):
        assert detect_bulk_extraction(0) is False

    def test_extreme_rows_is_bulk(self):
        assert detect_bulk_extraction(1_000_000) is True


# ── detect_shadow_endpoint ───────────────────────────────────────────────────

class TestShadowEndpoint:
    def test_known_function_is_not_shadow(self):
        assert detect_shadow_endpoint("RFC_READ_TABLE") is False

    def test_unknown_function_is_shadow(self):
        assert detect_shadow_endpoint("ZROGUE_EXFILTRATE") is True

    def test_empty_string_is_shadow(self):
        assert detect_shadow_endpoint("") is True

    def test_case_sensitive_matching(self):
        # "rfc_read_table" (lowercase) is NOT in the allowlist
        assert detect_shadow_endpoint("rfc_read_table") is True

    def test_connectivity_test_is_known(self):
        assert detect_shadow_endpoint("STFC_CONNECTION") is False


# ── run_detectors (orchestrator) ─────────────────────────────────────────────

class TestRunDetectors:
    def _ts(self, hour: int) -> datetime:
        return datetime(2026, 4, 7, hour, 0, tzinfo=timezone.utc)

    def test_all_clean(self):
        flags = run_detectors(
            rfc_function="RFC_READ_TABLE",
            rows_returned=100,
            timestamp=self._ts(10),
        )
        assert flags.is_off_hours is False
        assert flags.is_bulk_extraction is False
        assert flags.is_shadow_endpoint is False
        assert flags.flagged_at is None

    def test_off_hours_scenario(self):
        """POC demo scenario 1 — off-hours call."""
        flags = run_detectors(
            rfc_function="RFC_READ_TABLE",
            rows_returned=100,
            timestamp=self._ts(2),     # 02:00 UTC
        )
        assert flags.is_off_hours is True
        assert flags.flagged_at is not None

    def test_bulk_extraction_scenario(self):
        """POC demo scenario 2 — bulk extraction."""
        flags = run_detectors(
            rfc_function="RFC_READ_TABLE",
            rows_returned=50_000,
            timestamp=self._ts(10),
        )
        assert flags.is_bulk_extraction is True
        assert flags.flagged_at is not None

    def test_shadow_endpoint_scenario(self):
        """POC demo scenario 3 — shadow endpoint."""
        flags = run_detectors(
            rfc_function="ZROGUE_EXFILTRATE",
            rows_returned=0,
            timestamp=self._ts(10),
        )
        assert flags.is_shadow_endpoint is True
        assert flags.flagged_at is not None

    def test_all_three_flags_simultaneously(self):
        """Worst-case event: off-hours + bulk + shadow."""
        flags = run_detectors(
            rfc_function="ZUNKNOWN_FUNC",
            rows_returned=100_000,
            timestamp=self._ts(3),
        )
        assert flags.is_off_hours is True
        assert flags.is_bulk_extraction is True
        assert flags.is_shadow_endpoint is True

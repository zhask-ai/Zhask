"""Unit tests for M09 DLP rules."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "modules" / "m09-dlp"))

from dlp_rules import (
    BLOCKLISTED_FUNCTIONS,
    check_blocklisted_function,
    check_high_row_count,
    check_velocity,
    evaluate,
)


def _event(**overrides) -> dict:
    base = {
        "event_id": "test-001",
        "rfc_function": "RFC_PING",
        "client_ip": "10.0.1.1",
        "user_id": "USR001",
        "timestamp": "2026-04-07T10:00:00Z",
        "rows_returned": 50,
        "client_req_count_5m": 5,
    }
    base.update(overrides)
    return base


class TestHighRowCount:
    def test_below_threshold_no_alert(self):
        ev = _event(rows_returned=5_000)
        assert check_high_row_count(ev, threshold=10_000) is None

    def test_above_threshold_alert(self):
        ev = _event(rows_returned=15_000)
        alert = check_high_row_count(ev, threshold=10_000)
        assert alert is not None
        assert alert["rule_triggered"] == "HIGH_ROW_COUNT"
        assert alert["severity"] == "HIGH"

    def test_5x_threshold_is_critical(self):
        ev = _event(rows_returned=60_000)
        alert = check_high_row_count(ev, threshold=10_000)
        assert alert["severity"] == "CRITICAL"

    def test_exactly_at_threshold_no_alert(self):
        ev = _event(rows_returned=10_000)
        assert check_high_row_count(ev, threshold=10_000) is None


class TestBlocklistedFunction:
    def test_blocklisted_high_rows(self):
        ev = _event(rfc_function="RFC_READ_TABLE", rows_returned=6_000)
        alert = check_blocklisted_function(ev, row_threshold=5_000)
        assert alert is not None
        assert alert["rule_triggered"] == "BLOCKLISTED_FUNCTION"

    def test_blocklisted_low_rows_no_alert(self):
        ev = _event(rfc_function="RFC_READ_TABLE", rows_returned=100)
        assert check_blocklisted_function(ev, row_threshold=5_000) is None

    def test_non_blocklisted_high_rows_no_alert(self):
        ev = _event(rfc_function="RFC_PING", rows_returned=50_000)
        assert check_blocklisted_function(ev, row_threshold=5_000) is None


class TestVelocity:
    def test_below_threshold_no_alert(self):
        ev = _event(client_req_count_5m=30)
        assert check_velocity(ev, velocity_threshold=50) is None

    def test_above_threshold_alert(self):
        ev = _event(client_req_count_5m=55)
        alert = check_velocity(ev, velocity_threshold=50)
        assert alert is not None
        assert alert["rule_triggered"] == "VELOCITY_SPIKE"
        assert alert["severity"] == "MEDIUM"


class TestEvaluate:
    def test_clean_event_no_alerts(self):
        ev = _event()
        alerts = evaluate(ev, 10_000, 5_000, 50)
        assert alerts == []

    def test_bulk_extraction_triggers_two_rules(self):
        ev = _event(rfc_function="RFC_READ_TABLE", rows_returned=80_000)
        alerts = evaluate(ev, 10_000, 5_000, 50)
        rules = {a["rule_triggered"] for a in alerts}
        assert "HIGH_ROW_COUNT" in rules
        assert "BLOCKLISTED_FUNCTION" in rules

    def test_velocity_only(self):
        ev = _event(client_req_count_5m=60)
        alerts = evaluate(ev, 10_000, 5_000, 50)
        assert len(alerts) == 1
        assert alerts[0]["rule_triggered"] == "VELOCITY_SPIKE"

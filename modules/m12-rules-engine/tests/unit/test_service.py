"""Unit tests for M12 Rules Engine evaluation logic."""

import sys
from pathlib import Path

# Allow running tests before package install
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from integrishield.m12.models import ApiCallEvent, Scenario, Severity
from integrishield.m12.services import evaluate_event


def test_bulk_extraction_triggers_critical():
    event = ApiCallEvent(event_id="e1", bytes_out=15_000_000)
    alert = evaluate_event(event)
    assert alert is not None
    assert alert.scenario == Scenario.BULK_EXTRACTION
    assert alert.severity == Severity.CRITICAL


def test_off_hours_triggers_medium():
    event = ApiCallEvent(event_id="e2", off_hours=True, bytes_out=1000)
    alert = evaluate_event(event)
    assert alert is not None
    assert alert.scenario == Scenario.OFF_HOURS_RFC
    assert alert.severity == Severity.MEDIUM


def test_shadow_endpoint_triggers_critical():
    event = ApiCallEvent(event_id="e3", unknown_endpoint=True, bytes_out=500)
    alert = evaluate_event(event)
    assert alert is not None
    assert alert.scenario == Scenario.SHADOW_ENDPOINT
    assert alert.severity == Severity.CRITICAL


def test_normal_event_returns_none():
    event = ApiCallEvent(event_id="e4", bytes_out=100)
    alert = evaluate_event(event)
    assert alert is None


def test_evaluate_dict_input():
    raw = {"event_id": "e5", "bytes_out": 20_000_000, "off_hours": False, "unknown_endpoint": False}
    alert = evaluate_event(raw)
    assert alert is not None
    assert alert.scenario == Scenario.BULK_EXTRACTION


def test_bulk_extraction_priority_over_off_hours():
    """Bulk extraction (>10MB) should take priority even if off_hours is true."""
    event = ApiCallEvent(event_id="e6", bytes_out=12_000_000, off_hours=True)
    alert = evaluate_event(event)
    assert alert.scenario == Scenario.BULK_EXTRACTION

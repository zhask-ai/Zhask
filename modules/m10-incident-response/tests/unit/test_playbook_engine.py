"""Unit tests for M10 Incident Response playbook engine."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

import uuid
from datetime import datetime, timezone

import pytest

from integrishield.m10.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdateRequest,
    PlaybookAction,
)
from integrishield.m10.services.incident_store import IncidentStore
from integrishield.m10.services.playbook_engine import PlaybookEngine
from integrishield.m10.services.playbooks import PLAYBOOKS


def make_incident(severity: str = "critical", scenario: str = "bulk-extraction") -> Incident:
    return Incident(
        incident_id=str(uuid.uuid4()),
        alert_event_id=str(uuid.uuid4()),
        title=f"Test {scenario}",
        severity=IncidentSeverity(severity),
        scenario=scenario,
        source_ip="10.0.0.1",
        user_id="test_user",
        created_at=datetime.now(tz=timezone.utc),
        updated_at=datetime.now(tz=timezone.utc),
    )


# ─── Playbook matching ────────────────────────────────────────────────────────

def test_bulk_extraction_matches_critical_playbook():
    engine = PlaybookEngine()
    incident = make_incident("critical", "bulk-extraction")
    playbook = engine.match(incident)
    assert playbook is not None
    assert "BULK" in playbook.playbook_id or "bulk" in playbook.playbook_id.lower()


def test_shadow_endpoint_matches_shadow_playbook():
    engine = PlaybookEngine()
    incident = make_incident("critical", "shadow-endpoint")
    playbook = engine.match(incident)
    assert playbook is not None
    assert PlaybookAction.AUTO_CONTAIN in playbook.actions


def test_off_hours_matches_medium_playbook():
    engine = PlaybookEngine()
    incident = make_incident("medium", "off-hours-rfc")
    playbook = engine.match(incident)
    assert playbook is not None
    assert PlaybookAction.NOTIFY_SLACK in playbook.actions
    assert PlaybookAction.AUTO_CONTAIN not in playbook.actions


def test_low_severity_no_playbook_match():
    engine = PlaybookEngine()
    incident = make_incident("low", "off-hours-rfc")
    playbook = engine.match(incident)
    # Low severity has no defined playbooks in our set
    # (catch-all only covers critical/high/medium)
    assert playbook is None


def test_unknown_scenario_falls_to_catch_all():
    engine = PlaybookEngine()
    incident = make_incident("critical", "totally-unknown-scenario")
    playbook = engine.match(incident)
    assert playbook is not None
    assert playbook.playbook_id == "PB-DEFAULT-CATCH-ALL"


def test_specific_scenario_beats_catch_all():
    engine = PlaybookEngine()
    incident = make_incident("critical", "bulk-extraction")
    playbook = engine.match(incident)
    # Should NOT be the catch-all
    assert playbook is not None
    assert playbook.playbook_id != "PB-DEFAULT-CATCH-ALL"


# ─── Playbook execution ───────────────────────────────────────────────────────

def test_playbook_execute_returns_logs():
    engine = PlaybookEngine()
    incident = make_incident("critical", "bulk-extraction")
    playbook = engine.match(incident)
    assert playbook is not None
    logs = engine.execute(incident, playbook)
    assert len(logs) == len(playbook.actions)
    assert all(log.incident_id == incident.incident_id for log in logs)


def test_playbook_log_event_always_succeeds():
    engine = PlaybookEngine()
    incident = make_incident("medium", "off-hours-rfc")
    playbook = engine.match(incident)
    logs = engine.execute(incident, playbook)
    log_event_logs = [l for l in logs if l.action == PlaybookAction.LOG_EVENT]
    assert all(l.success for l in log_event_logs)


# ─── Incident store ───────────────────────────────────────────────────────────

def test_incident_store_create_and_retrieve():
    store = IncidentStore()
    incident = make_incident()
    store.create_incident(incident)
    retrieved = store.get_incident(incident.incident_id)
    assert retrieved is not None
    assert retrieved.incident_id == incident.incident_id


def test_incident_store_update_status():
    store = IncidentStore()
    incident = make_incident()
    store.create_incident(incident)
    req = IncidentUpdateRequest(status=IncidentStatus.CONTAINED)
    updated = store.update_incident(incident.incident_id, req)
    assert updated.status == IncidentStatus.CONTAINED


def test_incident_store_list_with_severity_filter():
    store = IncidentStore()
    store.create_incident(make_incident("critical", "bulk-extraction"))
    store.create_incident(make_incident("medium", "off-hours-rfc"))
    results, total = store.list_incidents(severity="critical")
    assert all(i.severity == IncidentSeverity.CRITICAL for i in results)


def test_incident_store_min_severity_filtering():
    """Low severity incidents below threshold should not appear in medium+ lists."""
    store = IncidentStore()
    store.create_incident(make_incident("low", "info"))
    store.create_incident(make_incident("critical", "bulk-extraction"))
    results, _ = store.list_incidents(severity="low")
    assert len(results) == 1
    results_critical, _ = store.list_incidents(severity="critical")
    assert len(results_critical) == 1


def test_incident_store_stats():
    store = IncidentStore()
    store.create_incident(make_incident("critical"))
    store.create_incident(make_incident("medium"))
    stats = store.stats()
    assert stats["total"] == 2
    assert stats["open"] == 2
    assert stats["critical"] == 1


def test_incident_store_open_count():
    store = IncidentStore()
    i1 = make_incident()
    i2 = make_incident()
    store.create_incident(i1)
    store.create_incident(i2)
    assert store.open_count() == 2
    store.update_incident(i1.incident_id, IncidentUpdateRequest(status=IncidentStatus.RESOLVED))
    assert store.open_count() == 1

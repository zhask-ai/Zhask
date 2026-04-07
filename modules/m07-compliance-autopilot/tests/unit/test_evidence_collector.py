"""Unit tests for M07 Compliance Autopilot."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

import pytest

from integrishield.m07.models import ControlStatus, EvidenceType, Framework
from integrishield.m07.services.compliance_engine import ComplianceEngine
from integrishield.m07.services.control_loader import ControlLoader
from integrishield.m07.services.report_generator import ReportGenerator

_CONTROLS_PATH = str(Path(__file__).resolve().parents[3] / "config" / "controls")


def make_engine() -> ComplianceEngine:
    loader = ControlLoader(_CONTROLS_PATH)
    loader.load()
    return ComplianceEngine(loader=loader, redis_client=None)


# ─── ControlLoader ────────────────────────────────────────────────────────────

def test_control_loader_loads_all_frameworks():
    loader = ControlLoader(_CONTROLS_PATH)
    count = loader.load()
    assert count >= 15  # 4 sox + 4 soc2 + 4 iso + 3 gdpr = 15 minimum


def test_control_loader_sox_controls():
    loader = ControlLoader(_CONTROLS_PATH)
    loader.load()
    sox = loader.get_for_framework(Framework.SOX)
    assert len(sox) >= 4
    ids = [c.control_id for c in sox]
    assert "SOX-ITGC-01" in ids


def test_control_loader_stream_mapping():
    loader = ControlLoader(_CONTROLS_PATH)
    loader.load()
    controls = loader.get_for_stream("integrishield:dlp_alerts")
    # DLP alerts should map to at least SOX and GDPR controls
    assert len(controls) >= 2


def test_control_loader_violation_stream():
    loader = ControlLoader(_CONTROLS_PATH)
    loader.load()
    # DLP alerts are violations for SOX-ITGC-04 and GDPR-Art32
    assert loader.is_violation_stream("SOX-ITGC-04", "integrishield:dlp_alerts")
    # API calls are not violations (they're evidence only)
    assert not loader.is_violation_stream("A.12.4.1", "integrishield:api_call_events")


# ─── ComplianceEngine ─────────────────────────────────────────────────────────

def test_engine_initial_state_not_assessed():
    engine = make_engine()
    assessments = engine.get_assessments()
    assert all(a.status == ControlStatus.NOT_ASSESSED for a in assessments)


def test_engine_dlp_alert_marks_sox_non_compliant():
    engine = make_engine()
    engine.ingest_event(
        "integrishield:dlp_alerts",
        {"event_id": "dlp-001", "alert_type": "bulk_export", "tenant_id": ""},
    )
    assessment = engine.get_assessment("SOX-ITGC-04")
    assert assessment is not None
    assert assessment.status == ControlStatus.NON_COMPLIANT
    assert assessment.violation_count >= 1


def test_engine_api_call_marks_compliant():
    engine = make_engine()
    engine.ingest_event(
        "integrishield:api_call_events",
        {"event_id": "api-001", "rfc_function": "BAPI_MATERIAL_GET_ALL"},
    )
    # A.12.4.1 should become COMPLIANT (not a violation stream)
    assessment = engine.get_assessment("A.12.4.1")
    assert assessment is not None
    assert assessment.status == ControlStatus.COMPLIANT
    assert assessment.violation_count == 0


def test_engine_evidence_stored():
    engine = make_engine()
    engine.ingest_event(
        "integrishield:anomaly_events",
        {"event_id": "ano-001", "anomaly_score": 0.95},
    )
    # CC7.2 tracks anomaly events
    evidence = engine.get_evidence("CC7.2")
    assert len(evidence) >= 1
    assert evidence[0].evidence_type == EvidenceType.ANOMALY


def test_engine_summary_sox():
    engine = make_engine()
    # Inject a violation
    engine.ingest_event(
        "integrishield:dlp_alerts",
        {"event_id": "dlp-002"},
    )
    summary = engine.get_summary(Framework.SOX)
    assert summary.framework == Framework.SOX
    assert summary.total_controls >= 4
    assert summary.non_compliant >= 1
    assert 0 <= summary.compliance_percentage <= 100


def test_engine_summary_all_not_assessed():
    engine = make_engine()
    summary = engine.get_summary(Framework.GDPR)
    assert summary.not_assessed == summary.total_controls
    assert summary.compliance_percentage == 0.0


# ─── ReportGenerator ─────────────────────────────────────────────────────────

def test_report_generator_json():
    engine = make_engine()
    engine.ingest_event("integrishield:dlp_alerts", {"event_id": "r-001"})
    generator = ReportGenerator(engine)
    from integrishield.m07.models import ReportRequest
    req = ReportRequest(framework=Framework.SOX)
    report_id = generator.generate(req)
    report = generator.get_json(report_id)
    assert report is not None
    assert report["framework"] == "sox"
    assert "controls" in report
    assert "summary" in report


def test_report_generator_csv():
    engine = make_engine()
    generator = ReportGenerator(engine)
    from integrishield.m07.models import ReportRequest
    req = ReportRequest(framework=Framework.SOC2, format="csv")
    report_id = generator.generate(req)
    csv_data = generator.get_csv(report_id)
    assert csv_data is not None
    assert "control_id" in csv_data
    assert "status" in csv_data


def test_report_not_found():
    engine = make_engine()
    generator = ReportGenerator(engine)
    assert generator.get_json("nonexistent") is None
    assert generator.get_csv("nonexistent") is None

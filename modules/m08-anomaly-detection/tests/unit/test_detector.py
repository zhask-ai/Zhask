"""Unit tests for M08 AnomalyDetector (uses a mock model)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "modules" / "m08-anomaly-detection"))


def _make_detector(anomaly_score: float, is_anomaly: bool):
    """Build a detector with a mocked model and producer."""
    from detector import AnomalyDetector

    mock_model = MagicMock()
    mock_model.score_samples.return_value = np.array([anomaly_score])
    mock_model.predict.return_value = np.array([-1 if is_anomaly else 1])

    mock_scaler = MagicMock()
    mock_scaler.transform.side_effect = lambda x: x  # identity transform

    with patch("detector.RedisStreamProducer") as MockProducer:
        mock_producer = MagicMock()
        MockProducer.return_value = mock_producer
        detector = AnomalyDetector(mock_model, mock_scaler, "redis://localhost", "anomaly_events")
        detector._producer = mock_producer
        return detector, mock_producer


def _analyzed_event(**overrides) -> dict:
    base = {
        "event_id": "test-event-001",
        "rfc_function": "RFC_READ_TABLE",
        "client_ip": "10.0.1.1",
        "user_id": "USR001",
        "timestamp": "2026-04-07T02:30:00Z",
        "hour_of_day": 2,
        "is_off_hours": 1,
        "is_weekend": 0,
        "rows_returned": 100,
        "rows_per_second": 200.0,
        "response_time_ms": 500,
        "client_req_count_5m": 5,
        "unique_functions_10m": 3,
        "endpoint_entropy_10m": 1.5,
        "is_known_endpoint": 1,
    }
    base.update(overrides)
    return base


class TestAnomalyDetector:
    def test_normal_event_not_published(self):
        detector, producer = _make_detector(anomaly_score=-0.1, is_anomaly=False)
        result = detector.process("ev-001", _analyzed_event())
        producer.publish.assert_not_called()
        assert result["is_anomaly"] is False

    def test_anomaly_event_published(self):
        detector, producer = _make_detector(anomaly_score=-0.8, is_anomaly=True)
        result = detector.process("ev-002", _analyzed_event(is_off_hours=1))
        producer.publish.assert_called_once()
        assert result["is_anomaly"] is True
        assert result["severity"] == "CRITICAL"

    def test_bulk_extraction_type(self):
        detector, producer = _make_detector(anomaly_score=-0.75, is_anomaly=True)
        event = _analyzed_event(rows_returned=80_000, is_off_hours=0, is_known_endpoint=1)
        result = detector.process("ev-003", event)
        assert result["anomaly_type"] == "BULK_EXTRACTION"

    def test_shadow_endpoint_type(self):
        detector, producer = _make_detector(anomaly_score=-0.9, is_anomaly=True)
        event = _analyzed_event(is_known_endpoint=0)
        result = detector.process("ev-004", event)
        assert result["anomaly_type"] == "SHADOW_ENDPOINT"

    def test_feature_snapshot_included(self):
        detector, producer = _make_detector(anomaly_score=-0.85, is_anomaly=True)
        result = detector.process("ev-005", _analyzed_event())
        assert "feature_snapshot" in result
        assert "rows_returned" in result["feature_snapshot"]

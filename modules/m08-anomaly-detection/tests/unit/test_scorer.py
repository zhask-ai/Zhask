"""Unit tests for M08 anomaly scorer."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

# Import scorer from the module directory
sys.path.insert(0, str(REPO_ROOT / "modules" / "m08-anomaly-detection"))

from scorer import infer_anomaly_type, score_to_severity


class TestScoreToSeverity:
    def test_critical(self):
        assert score_to_severity(-0.8) == "CRITICAL"
        assert score_to_severity(-1.0) == "CRITICAL"

    def test_high(self):
        assert score_to_severity(-0.6) == "HIGH"
        assert score_to_severity(-0.51) == "HIGH"

    def test_medium(self):
        assert score_to_severity(-0.4) == "MEDIUM"

    def test_low(self):
        assert score_to_severity(-0.2) == "LOW"
        assert score_to_severity(0.0) == "LOW"
        assert score_to_severity(0.1) == "LOW"


class TestInferAnomalyType:
    def test_shadow_endpoint_takes_priority(self):
        features = {
            "is_known_endpoint": 0,
            "rows_returned": 80_000,
            "is_off_hours": 1,
            "client_req_count_5m": 100,
        }
        assert infer_anomaly_type(features) == "SHADOW_ENDPOINT"

    def test_bulk_extraction(self):
        features = {
            "is_known_endpoint": 1,
            "rows_returned": 50_000,
            "is_off_hours": 0,
            "client_req_count_5m": 5,
        }
        assert infer_anomaly_type(features) == "BULK_EXTRACTION"

    def test_off_hours(self):
        features = {
            "is_known_endpoint": 1,
            "rows_returned": 100,
            "is_off_hours": 1,
            "client_req_count_5m": 2,
        }
        assert infer_anomaly_type(features) == "OFF_HOURS"

    def test_velocity_spike(self):
        features = {
            "is_known_endpoint": 1,
            "rows_returned": 50,
            "is_off_hours": 0,
            "client_req_count_5m": 60,
        }
        assert infer_anomaly_type(features) == "VELOCITY_SPIKE"

    def test_unknown(self):
        features = {
            "is_known_endpoint": 1,
            "rows_returned": 10,
            "is_off_hours": 0,
            "client_req_count_5m": 3,
        }
        assert infer_anomaly_type(features) == "UNKNOWN"

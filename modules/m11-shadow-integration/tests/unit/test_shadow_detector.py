"""Unit tests for M11 shadow endpoint detection."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "modules" / "m11-shadow-integration"))

from endpoint_registry import load_registry
from shadow_detector import ShadowDetector


KNOWN = frozenset(["RFC_PING", "RFC_READ_TABLE", "BAPI_CUSTOMER_GETLIST"])


def _make_detector() -> tuple:
    with patch("shadow_detector.RedisStreamProducer") as MockProducer:
        mock_producer = MagicMock()
        MockProducer.return_value = mock_producer
        detector = ShadowDetector(KNOWN, "redis://localhost", "shadow_alerts")
        detector._producer = mock_producer
        return detector, mock_producer


def _event(rfc_function: str) -> dict:
    return {
        "event_id": "test-001",
        "rfc_function": rfc_function,
        "client_ip": "10.0.1.1",
        "user_id": "USR001",
        "timestamp": "2026-04-07T10:00:00Z",
    }


class TestShadowDetector:
    def test_known_endpoint_no_alert(self):
        detector, producer = _make_detector()
        result = detector.process("ev-001", _event("RFC_PING"))
        assert result is None
        producer.publish.assert_not_called()

    def test_unknown_endpoint_triggers_alert(self):
        detector, producer = _make_detector()
        result = detector.process("ev-002", _event("ZRFC_EXFIL_DATA"))
        assert result is not None
        producer.publish.assert_called_once()
        assert result["rfc_function"] == "ZRFC_EXFIL_DATA"

    def test_first_seen_flag(self):
        detector, _ = _make_detector()
        result = detector.process("ev-003", _event("ZRFC_EXFIL_DATA"))
        assert result["first_seen"] is True

    def test_second_occurrence_not_first_seen(self):
        detector, _ = _make_detector()
        detector.process("ev-004", _event("ZRFC_EXFIL_DATA"))
        result2 = detector.process("ev-005", _event("ZRFC_EXFIL_DATA"))
        assert result2["first_seen"] is False
        assert result2["times_seen_today"] == 2

    def test_first_seen_is_critical(self):
        detector, _ = _make_detector()
        result = detector.process("ev-006", _event("NEW_UNKNOWN"))
        assert result["severity"] == "CRITICAL"

    def test_severity_degrades_with_repetition(self):
        detector, _ = _make_detector()
        results = [
            detector.process(f"ev-{i}", _event("REPEATED_UNKNOWN"))
            for i in range(7)
        ]
        # First call: CRITICAL, 2-4: HIGH, 5+: MEDIUM
        assert results[0]["severity"] == "CRITICAL"
        assert results[1]["severity"] == "HIGH"
        assert results[5]["severity"] == "MEDIUM"


class TestEndpointRegistry:
    def test_defaults_loaded(self):
        registry = load_registry()
        assert "RFC_PING" in registry
        assert "RFC_READ_TABLE" in registry

    def test_shadow_fn_not_in_registry(self):
        registry = load_registry()
        assert "ZRFC_EXFIL_DATA" not in registry
        assert "UNKNOWN_BACKDOOR_FUNC" not in registry

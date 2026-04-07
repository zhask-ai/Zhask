"""Unit tests for sliding window state (m03)."""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from ml.training.feature_engineering import SlidingWindowState


def _dt(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 4, 7, hour, minute, 0, tzinfo=timezone.utc)


class TestSlidingWindowState:
    def test_client_req_count_5m_empty(self):
        state = SlidingWindowState()
        state.add(_dt(9), "10.0.1.1", "RFC_PING")
        assert state.client_req_count_5m("10.0.1.1") == 1

    def test_client_req_count_5m_multiple_clients(self):
        state = SlidingWindowState()
        state.add(_dt(9, 0), "10.0.1.1", "RFC_PING")
        state.add(_dt(9, 1), "10.0.1.2", "RFC_PING")
        state.add(_dt(9, 2), "10.0.1.1", "RFC_PING")
        assert state.client_req_count_5m("10.0.1.1") == 2
        assert state.client_req_count_5m("10.0.1.2") == 1

    def test_client_req_count_5m_eviction(self):
        state = SlidingWindowState(window_5m_secs=60)  # 1-minute window for test speed
        state.add(_dt(9, 0), "10.0.1.1", "RFC_PING")
        # Add event 2 minutes later — old event should be evicted
        state.add(_dt(9, 2), "10.0.1.1", "RFC_PING")
        # Only the 9:02 event is in window
        assert state.client_req_count_5m("10.0.1.1") == 1

    def test_unique_functions_10m(self):
        state = SlidingWindowState()
        state.add(_dt(9, 0), "10.0.1.1", "RFC_PING")
        state.add(_dt(9, 1), "10.0.1.2", "RFC_READ_TABLE")
        state.add(_dt(9, 2), "10.0.1.1", "RFC_PING")  # duplicate
        assert state.unique_functions_10m() == 2

    def test_endpoint_entropy_single_function(self):
        state = SlidingWindowState()
        for i in range(5):
            state.add(_dt(9, i), "10.0.1.1", "RFC_PING")
        # All same function → entropy = 0
        assert state.endpoint_entropy_10m() == pytest.approx(0.0)

    def test_endpoint_entropy_uniform(self):
        import math
        state = SlidingWindowState()
        # 4 distinct functions, 1 call each → entropy = log2(4) = 2.0
        for fn in ["RFC_PING", "RFC_READ_TABLE", "BAPI_CUSTOMER_GETLIST", "STFC_CONNECTION"]:
            state.add(_dt(9, 0), "10.0.1.1", fn)
        assert state.endpoint_entropy_10m() == pytest.approx(math.log2(4), rel=1e-3)

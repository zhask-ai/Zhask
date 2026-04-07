"""
Feature extraction for RFC anomaly detection.

Used by:
  - ml/training/train_model.py  (offline, on JSON seed data)
  - modules/m03-traffic-analyzer (online, per-event from Redis Stream)

All feature functions are pure — no global state — so they can be tested
and called from either context.
"""

import math
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Known RFC allowlist (single source of truth — duplicated in m11 for isolation)
# ---------------------------------------------------------------------------
KNOWN_RFC_FUNCTIONS: frozenset[str] = frozenset(
    [
        "RFC_READ_TABLE",
        "BAPI_MATERIAL_GETLIST",
        "BAPI_CUSTOMER_GETLIST",
        "BAPI_SALESORDER_GETLIST",
        "BAPI_PO_GETDETAIL",
        "RFC_GET_SYSTEM_INFO",
        "SUSR_USER_AUTH_FOR_OBJ_GET",
        "BAPI_USER_GETLIST",
        "BAPI_COMPANYCODE_GETLIST",
        "RFC_FUNCTION_SEARCH",
        "BAPI_EMPLOYEE_GETDATA",
        "BAPI_VENDOR_GETLIST",
        "BAPI_PRODORD_GET_DETAIL",
        "RFC_PING",
        "STFC_CONNECTION",
    ]
)

FEATURE_NAMES = [
    "hour_of_day",
    "is_off_hours",
    "is_weekend",
    "rows_returned",
    "rows_per_second",
    "response_time_ms",
    "client_req_count_5m",
    "unique_functions_10m",
    "endpoint_entropy_10m",
    "is_known_endpoint",
]


# ---------------------------------------------------------------------------
# Stateless per-event features
# ---------------------------------------------------------------------------

def parse_timestamp(ts_str: str) -> datetime:
    """Parse ISO 8601 UTC string to datetime."""
    ts_str = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(ts_str)


def hour_of_day(ts: datetime) -> int:
    return ts.hour


def is_off_hours(ts: datetime) -> int:
    """1 if call is outside Mon–Fri 08:00–18:00, else 0."""
    if ts.weekday() >= 5:
        return 1
    if ts.hour < 8 or ts.hour >= 18:
        return 1
    return 0


def is_weekend(ts: datetime) -> int:
    return 1 if ts.weekday() >= 5 else 0


def rows_per_second(rows_returned: int, response_time_ms: int) -> float:
    secs = max(response_time_ms / 1000.0, 0.001)
    return rows_returned / secs


def is_known_endpoint(rfc_function: str) -> int:
    return 1 if rfc_function in KNOWN_RFC_FUNCTIONS else 0


# ---------------------------------------------------------------------------
# Windowed / stateful features (computed by SlidingWindowState)
# ---------------------------------------------------------------------------

class SlidingWindowState:
    """
    Maintains two sliding windows for windowed feature computation:
      - 5-minute window: per-client request counts
      - 10-minute window: global RFC function diversity
    """

    def __init__(self, window_5m_secs: int = 300, window_10m_secs: int = 600):
        self._w5 = window_5m_secs
        self._w10 = window_10m_secs
        # (timestamp_epoch, client_ip)
        self._client_events: deque[tuple[float, str]] = deque()
        # (timestamp_epoch, rfc_function)
        self._function_events: deque[tuple[float, str]] = deque()

    def _evict(self, epoch: float) -> None:
        """Remove entries older than the relevant window."""
        cutoff5 = epoch - self._w5
        cutoff10 = epoch - self._w10
        while self._client_events and self._client_events[0][0] < cutoff5:
            self._client_events.popleft()
        while self._function_events and self._function_events[0][0] < cutoff10:
            self._function_events.popleft()

    def add(self, ts: datetime, client_ip: str, rfc_function: str) -> None:
        epoch = ts.timestamp()
        self._evict(epoch)
        self._client_events.append((epoch, client_ip))
        self._function_events.append((epoch, rfc_function))

    def client_req_count_5m(self, client_ip: str) -> int:
        return sum(1 for _, ip in self._client_events if ip == client_ip)

    def unique_functions_10m(self) -> int:
        return len({fn for _, fn in self._function_events})

    def endpoint_entropy_10m(self) -> float:
        counts = Counter(fn for _, fn in self._function_events)
        total = sum(counts.values())
        if total == 0:
            return 0.0
        return -sum(
            (c / total) * math.log2(c / total) for c in counts.values() if c > 0
        )


# ---------------------------------------------------------------------------
# Offline batch feature extraction (for training)
# ---------------------------------------------------------------------------

def extract_features_batch(events: list[dict]) -> list[dict]:
    """
    Extract features from a list of event dicts (sorted by timestamp).
    Returns a list of feature dicts aligned to the input events.
    Used by train_model.py.
    """
    events_sorted = sorted(events, key=lambda e: e["timestamp"])
    state = SlidingWindowState()
    feature_rows = []

    for ev in events_sorted:
        ts = parse_timestamp(ev["timestamp"])
        client_ip = ev["client_ip"]
        rfc_fn = ev["rfc_function"]
        rows = int(ev.get("rows_returned", 0))
        rt_ms = int(ev.get("response_time_ms", 1))

        # Update window state BEFORE reading (so current event counts in window)
        state.add(ts, client_ip, rfc_fn)

        feature_rows.append(
            {
                "event_id": ev.get("event_id", ""),
                "label": ev.get("label", "normal"),
                "hour_of_day": hour_of_day(ts),
                "is_off_hours": is_off_hours(ts),
                "is_weekend": is_weekend(ts),
                "rows_returned": rows,
                "rows_per_second": rows_per_second(rows, rt_ms),
                "response_time_ms": rt_ms,
                "client_req_count_5m": state.client_req_count_5m(client_ip),
                "unique_functions_10m": state.unique_functions_10m(),
                "endpoint_entropy_10m": state.endpoint_entropy_10m(),
                "is_known_endpoint": is_known_endpoint(rfc_fn),
            }
        )

    return feature_rows


def features_to_matrix(feature_rows: list[dict]) -> tuple:
    """
    Convert feature dicts to numpy arrays X, y, event_ids.
    Returns (X: ndarray, y: ndarray, event_ids: list[str])
    """
    import numpy as np

    X = np.array([[row[f] for f in FEATURE_NAMES] for row in feature_rows], dtype=float)
    y = np.array([0 if row["label"] == "normal" else 1 for row in feature_rows])
    event_ids = [row["event_id"] for row in feature_rows]
    return X, y, event_ids

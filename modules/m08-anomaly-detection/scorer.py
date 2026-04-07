"""
Map IsolationForest anomaly scores to human-readable severity levels
and infer the most likely anomaly type from feature values.
"""

from typing import Any

# Score thresholds (IsolationForest score_samples output, range roughly [-1, 0])
CRITICAL_THRESHOLD = -0.7
HIGH_THRESHOLD = -0.5
MEDIUM_THRESHOLD = -0.3


def score_to_severity(score: float) -> str:
    if score < CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score < HIGH_THRESHOLD:
        return "HIGH"
    if score < MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def infer_anomaly_type(features: dict[str, Any]) -> str:
    """
    Best-effort classification of *why* an event was flagged.
    Checked in priority order — an event can only have one primary type.
    """
    if not features.get("is_known_endpoint", 1):
        return "SHADOW_ENDPOINT"
    if int(features.get("rows_returned", 0)) > 10_000:
        return "BULK_EXTRACTION"
    if features.get("is_off_hours", 0):
        return "OFF_HOURS"
    if int(features.get("client_req_count_5m", 0)) > 50:
        return "VELOCITY_SPIKE"
    return "UNKNOWN"

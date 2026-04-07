"""
IsolationForest inference wrapper for M08.

Takes an enriched analyzed_event dict, runs the model, and returns
a fully-formed anomaly_event dict ready for publishing.
"""

import logging
import uuid
from typing import Any, Optional

import numpy as np

from scorer import infer_anomaly_type, score_to_severity
from shared.event_bus.producer import RedisStreamProducer

logger = logging.getLogger(__name__)

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


class AnomalyDetector:
    def __init__(self, model, scaler, redis_url: str, output_stream: str):
        self._model = model
        self._scaler = scaler
        self._producer = RedisStreamProducer(redis_url, output_stream)

    def process(self, event_id: str, data: dict[str, Any]) -> Optional[dict]:
        """
        Run inference on an analyzed_event.
        Publishes to anomaly_events stream.
        Returns the anomaly event dict (whether anomaly or not, for logging).
        """
        try:
            feature_vec = np.array(
                [[float(data.get(f, 0)) for f in FEATURE_NAMES]]
            )
        except (ValueError, TypeError) as e:
            logger.warning("Could not extract features from event %s: %s", event_id, e)
            return None

        scaled = self._scaler.transform(feature_vec)
        score = float(self._model.score_samples(scaled)[0])
        prediction = int(self._model.predict(scaled)[0])  # -1 = anomaly, 1 = normal
        is_anomaly = prediction == -1

        severity = score_to_severity(score)
        anomaly_type = infer_anomaly_type(data) if is_anomaly else "UNKNOWN"

        anomaly_event = {
            "event_id": str(uuid.uuid4()),
            "original_event_id": data.get("event_id", ""),
            "rfc_function": data.get("rfc_function", ""),
            "client_ip": data.get("client_ip", ""),
            "user_id": data.get("user_id", ""),
            "timestamp": data.get("timestamp", ""),
            "anomaly_score": round(score, 4),
            "severity": severity,
            "anomaly_type": anomaly_type,
            "is_anomaly": is_anomaly,
            "feature_snapshot": {f: data.get(f) for f in FEATURE_NAMES},
        }

        if is_anomaly:
            logger.warning(
                "ANOMALY detected | type=%s severity=%s score=%.3f rfc=%s client=%s",
                anomaly_type,
                severity,
                score,
                data.get("rfc_function"),
                data.get("client_ip"),
            )
            self._producer.publish(anomaly_event)
        else:
            logger.debug("Normal event score=%.3f rfc=%s", score, data.get("rfc_function"))

        return anomaly_event

"""
M08 Anomaly Detection — entry point.

Reads enriched events from `analyzed_events`, runs IsolationForest inference,
publishes confirmed anomalies to `anomaly_events`.
"""

import logging
import signal
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import config
from detector import AnomalyDetector
from model_loader import load_model
from shared.event_bus.consumer import RedisStreamConsumer

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("m08")


class AnomalyDetectionConsumer(RedisStreamConsumer):
    def __init__(self, detector: AnomalyDetector):
        super().__init__(
            redis_url=config.REDIS_URL,
            stream_name=config.INPUT_STREAM,
            consumer_name=config.CONSUMER_NAME,
        )
        self._detector = detector

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        self._detector.process(event_id, data)


def main():
    logger.info("M08 Anomaly Detection starting — loading model from %s", config.MODEL_PATH)
    model, scaler = load_model(config.MODEL_PATH)

    detector = AnomalyDetector(model, scaler, config.REDIS_URL, config.OUTPUT_STREAM)
    consumer = AnomalyDetectionConsumer(detector)

    def _shutdown(sig, frame):
        logger.info("Shutting down M08…")
        consumer.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("Listening on stream '%s' → publishing to '%s'", config.INPUT_STREAM, config.OUTPUT_STREAM)
    consumer.run()


if __name__ == "__main__":
    main()

"""
M11 Shadow Integration Detector — entry point.

Reads raw RFC events from `rfc_events` (before feature enrichment),
checks against the known endpoint allowlist, publishes shadow alerts.
"""

import logging
import signal
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import config
from endpoint_registry import load_registry
from shadow_detector import ShadowDetector
from shared.event_bus.consumer import RedisStreamConsumer

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("m11")


class ShadowConsumer(RedisStreamConsumer):
    def __init__(self, detector: ShadowDetector):
        super().__init__(
            redis_url=config.REDIS_URL,
            stream_name=config.INPUT_STREAM,
            consumer_name=config.CONSUMER_NAME,
        )
        self._detector = detector

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        self._detector.process(event_id, data)


def main():
    known = load_registry(config.KNOWN_ENDPOINTS_FILE)
    logger.info("Loaded %d known RFC endpoints", len(known))

    detector = ShadowDetector(known, config.REDIS_URL, config.OUTPUT_STREAM)
    consumer = ShadowConsumer(detector)

    def _shutdown(sig, frame):
        logger.info("Shutting down M11…")
        consumer.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("M11 Shadow Integration starting — %s → %s", config.INPUT_STREAM, config.OUTPUT_STREAM)
    consumer.run()


if __name__ == "__main__":
    main()

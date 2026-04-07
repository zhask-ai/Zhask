"""
M03 Traffic Analyzer — entry point.

Reads raw RFC events from `rfc_events` stream, enriches with features,
publishes to `analyzed_events` stream.
"""

import logging
import signal
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import config
from analyzer import TrafficAnalyzer
from shared.event_bus.consumer import RedisStreamConsumer

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("m03")


class TrafficAnalyzerConsumer(RedisStreamConsumer):
    def __init__(self):
        super().__init__(
            redis_url=config.REDIS_URL,
            stream_name=config.INPUT_STREAM,
            consumer_name=config.CONSUMER_NAME,
            group_name=config.GROUP_NAME,
        )
        self._analyzer = TrafficAnalyzer(config.REDIS_URL, config.OUTPUT_STREAM)

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        self._analyzer.process(event_id, data)


def main():
    consumer = TrafficAnalyzerConsumer()

    def _shutdown(sig, frame):
        logger.info("Shutting down M03…")
        consumer.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("M03 Traffic Analyzer starting — %s → %s", config.INPUT_STREAM, config.OUTPUT_STREAM)
    consumer.run()


if __name__ == "__main__":
    main()

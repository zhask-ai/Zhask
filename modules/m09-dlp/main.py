"""
M09 DLP — entry point.

Reads enriched events from `analyzed_events`, applies DLP rules,
publishes alerts to `dlp_alerts` stream.
"""

import logging
import signal
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import config
from dlp_rules import evaluate
from shared.event_bus.consumer import RedisStreamConsumer
from shared.event_bus.producer import RedisStreamProducer

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("m09")


class DlpConsumer(RedisStreamConsumer):
    def __init__(self):
        super().__init__(
            redis_url=config.REDIS_URL,
            stream_name=config.INPUT_STREAM,
            consumer_name=config.CONSUMER_NAME,
            group_name=config.GROUP_NAME,
        )
        self._producer = RedisStreamProducer(config.REDIS_URL, config.OUTPUT_STREAM)

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        alerts = evaluate(
            data,
            high_row_threshold=config.HIGH_ROW_COUNT_THRESHOLD,
            blocklist_row_threshold=config.BLOCKLIST_ROW_THRESHOLD,
            velocity_threshold=config.VELOCITY_THRESHOLD,
        )
        for alert in alerts:
            logger.warning(
                "DLP ALERT | rule=%s severity=%s rows=%d rfc=%s client=%s",
                alert["rule_triggered"],
                alert["severity"],
                alert["rows_returned"],
                alert["rfc_function"],
                alert["client_ip"],
            )
            self._producer.publish(alert)


def main():
    consumer = DlpConsumer()

    def _shutdown(sig, frame):
        logger.info("Shutting down M09…")
        consumer.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("M09 DLP starting — %s → %s", config.INPUT_STREAM, config.OUTPUT_STREAM)
    consumer.run()


if __name__ == "__main__":
    main()

"""Compliance event consumer for M07."""

from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[8] / "shared"))

try:
    from shared.event_bus.consumer import RedisStreamConsumer
except ImportError:
    from integrishield.m07.services._consumer_base import RedisStreamConsumer  # type: ignore

import redis as redis_lib

from integrishield.m07.config import settings
from integrishield.m07.services.compliance_engine import ComplianceEngine

logger = logging.getLogger(__name__)


class ComplianceConsumer(RedisStreamConsumer):
    """Consumes events from a Redis stream and feeds them to ComplianceEngine."""

    def __init__(
        self,
        redis_url: str,
        stream_name: str,
        consumer_name: str,
        group_name: str,
        engine: ComplianceEngine,
        publisher: redis_lib.Redis | None = None,
    ) -> None:
        super().__init__(
            redis_url=redis_url,
            stream_name=stream_name,
            consumer_name=consumer_name,
            group_name=group_name,
        )
        self._engine = engine
        self._stream_name = stream_name
        self._publisher = publisher

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        evidence_items = self._engine.ingest_event(self._stream_name, data)
        if evidence_items:
            self._publish_evidence(evidence_items)
            logger.debug(
                "m07 ingested %d evidence items from %s for event %s",
                len(evidence_items),
                self._stream_name,
                event_id,
            )

    def _publish_evidence(self, items) -> None:
        if self._publisher is None:
            return
        try:
            for item in items:
                self._publisher.xadd(
                    settings.publish_evidence_stream,
                    {"data": item.model_dump_json()},
                )
        except Exception:
            logger.exception("m07 failed to publish evidence")

"""Alert consumer for M10 Incident Response."""

from __future__ import annotations

import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[8] / "shared"))

try:
    from shared.event_bus.consumer import RedisStreamConsumer
except ImportError:
    from integrishield.m10.services._consumer_base import RedisStreamConsumer  # type: ignore

import redis as redis_lib

from integrishield.m10.config import settings
from integrishield.m10.models import (
    Incident,
    IncidentEvent,
    IncidentSeverity,
    IncidentStatus,
)

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"critical": IncidentSeverity.CRITICAL, "high": IncidentSeverity.HIGH, "medium": IncidentSeverity.MEDIUM, "low": IncidentSeverity.LOW}
_MIN_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _parse_severity(raw: Any) -> IncidentSeverity:
    s = str(raw).lower() if raw else "medium"
    return _SEVERITY_MAP.get(s, IncidentSeverity.MEDIUM)


class AlertConsumer(RedisStreamConsumer):
    """Consumes alert/anomaly/dlp events and creates incidents."""

    def __init__(
        self,
        redis_url: str,
        stream_name: str,
        consumer_name: str,
        group_name: str,
        store,
        engine,
        redis_publisher: redis_lib.Redis | None = None,
    ) -> None:
        super().__init__(
            redis_url=redis_url,
            stream_name=stream_name,
            consumer_name=consumer_name,
            group_name=group_name,
        )
        self._store = store
        self._engine = engine
        self._publisher = redis_publisher
        self._min_severity = settings.min_severity_for_incident

    def handle_event(self, event_id: str, data: dict[str, Any]) -> None:
        severity_val = data.get("severity", "medium")
        if _MIN_SEVERITY_ORDER.get(str(severity_val).lower(), 99) > _MIN_SEVERITY_ORDER.get(self._min_severity, 2):
            return  # below threshold

        incident = self._build_incident(event_id, data)
        self._store.create_incident(incident)

        # Match and execute playbook
        playbook = self._engine.match(incident)
        if playbook:
            incident = incident.model_copy(update={
                "playbook_id": playbook.playbook_id,
                "containment_applied": playbook.auto_contain,
            })
            self._store.create_incident(incident)
            logs = self._engine.execute(incident, playbook)
            for log in logs:
                self._store.add_execution_log(log)

        self._publish_incident_event(incident, "created")
        logger.info(
            "m10 incident created: %s [%s/%s] playbook=%s",
            incident.incident_id,
            incident.severity.value,
            incident.scenario,
            incident.playbook_id or "none",
        )

    def _build_incident(self, event_id: str, data: dict) -> Incident:
        severity = _parse_severity(data.get("severity"))
        scenario = str(data.get("scenario", data.get("alert_type", "unknown")))
        source_ip = str(data.get("source_ip", ""))
        user_id = str(data.get("user_id", data.get("credential_id", "")))
        detail = str(data.get("detail", data.get("message", "")))
        title = f"{scenario.replace('-', ' ').title()} — {detail[:80]}" if detail else f"{scenario.replace('-', ' ').title()} detected"

        return Incident(
            incident_id=str(uuid.uuid4()),
            alert_event_id=str(data.get("event_id", event_id)),
            title=title,
            severity=severity,
            status=IncidentStatus.OPEN,
            scenario=scenario,
            source_ip=source_ip,
            user_id=user_id,
            tenant_id=str(data.get("tenant_id", "")),
            created_at=datetime.now(tz=timezone.utc),
            updated_at=datetime.now(tz=timezone.utc),
        )

    def _publish_incident_event(self, incident: Incident, action: str) -> None:
        if self._publisher is None:
            return
        try:
            event = IncidentEvent(
                event_id=str(uuid.uuid4()),
                incident_id=incident.incident_id,
                alert_event_id=incident.alert_event_id,
                action=action,
                severity=incident.severity,
                tenant_id=incident.tenant_id,
            )
            self._publisher.xadd(settings.publish_stream, {"data": event.model_dump_json()})
        except Exception:
            logger.exception("m10 failed to publish incident event")

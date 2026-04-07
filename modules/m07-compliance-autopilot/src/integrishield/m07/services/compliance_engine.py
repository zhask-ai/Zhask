"""Compliance engine — manages control assessments and evidence collection."""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import redis as redis_lib

from integrishield.m07.config import settings
from integrishield.m07.models import (
    ComplianceAlertEvent,
    ComplianceSummary,
    ControlAssessment,
    ControlStatus,
    EvidenceItem,
    EvidenceType,
    Framework,
)
from integrishield.m07.services.control_loader import ControlLoader

logger = logging.getLogger(__name__)

# Stream → evidence type mapping
_STREAM_EVIDENCE_TYPE: dict[str, EvidenceType] = {
    "integrishield:api_call_events": EvidenceType.API_CALL_LOG,
    "integrishield:anomaly_events": EvidenceType.ANOMALY,
    "integrishield:dlp_alerts": EvidenceType.DLP_VIOLATION,
    "integrishield:shadow_alerts": EvidenceType.SHADOW_ENDPOINT,
    "integrishield:alert_events": EvidenceType.ALERT,
}


class ComplianceEngine:
    """In-memory compliance state with PostgreSQL persistence (best-effort)."""

    def __init__(self, loader: ControlLoader, redis_client: redis_lib.Redis | None = None) -> None:
        self._loader = loader
        self._redis = redis_client
        self._engine = None

        # In-memory stores
        self._assessments: dict[str, ControlAssessment] = {}
        self._evidence: dict[str, list[EvidenceItem]] = defaultdict(list)

        # Initialise assessments for all loaded controls
        self._init_assessments()

    def _init_assessments(self) -> None:
        for ctrl in self._loader.get_all().values():
            key = ctrl.control_id
            if key not in self._assessments:
                self._assessments[key] = ControlAssessment(
                    control_id=ctrl.control_id,
                    framework=ctrl.framework,
                    title=ctrl.title,
                    status=ControlStatus.NOT_ASSESSED,
                )

    def connect_db(self, database_url: str) -> bool:
        try:
            from sqlalchemy import create_engine, text

            self._engine = create_engine(database_url, pool_pre_ping=True, pool_size=3)
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            self._create_tables()
            logger.info("m07 PostgreSQL connected")
            return True
        except Exception as exc:
            logger.warning("m07 PostgreSQL unavailable: %s — using in-memory only", exc)
            self._engine = None
            return False

    def _create_tables(self) -> None:
        from integrishield.m07.db_models import Base

        Base.metadata.create_all(bind=self._engine)

    def ingest_event(self, stream_name: str, event_data: dict[str, Any]) -> list[EvidenceItem]:
        """Process an event, creating evidence items for matching controls."""
        controls = self._loader.get_for_stream(stream_name)
        if not controls:
            return []

        evidence_type = _STREAM_EVIDENCE_TYPE.get(stream_name, EvidenceType.API_CALL_LOG)
        created: list[EvidenceItem] = []

        for ctrl in controls:
            is_violation = self._loader.is_violation_stream(ctrl.control_id, stream_name)
            summary = self._build_summary(stream_name, event_data, ctrl.control_id)
            event_id = str(event_data.get("event_id", uuid.uuid4()))

            item = EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                control_id=ctrl.control_id,
                framework=ctrl.framework,
                event_id=event_id,
                evidence_type=evidence_type,
                tenant_id=str(event_data.get("tenant_id", "")),
                summary=summary,
                raw_payload=event_data,
                is_violation=is_violation,
            )

            self._evidence[ctrl.control_id].append(item)
            # Keep max 500 evidence items per control
            if len(self._evidence[ctrl.control_id]) > 500:
                self._evidence[ctrl.control_id] = self._evidence[ctrl.control_id][-500:]

            self._update_assessment(ctrl.control_id, item)
            created.append(item)

            # Publish compliance alert if violation
            if is_violation:
                self._publish_alert(item)

        return created

    def _update_assessment(self, control_id: str, evidence: EvidenceItem) -> None:
        assessment = self._assessments.get(control_id)
        if assessment is None:
            return

        evidence_count = len(self._evidence[control_id])
        violation_count = sum(1 for e in self._evidence[control_id] if e.is_violation)

        new_status = (
            ControlStatus.NON_COMPLIANT
            if violation_count > 0
            else ControlStatus.COMPLIANT
            if evidence_count > 0
            else ControlStatus.NOT_ASSESSED
        )

        self._assessments[control_id] = assessment.model_copy(
            update={
                "status": new_status,
                "evidence_count": evidence_count,
                "violation_count": violation_count,
                "last_assessed_at": datetime.now(tz=timezone.utc),
                "last_violation_at": (
                    datetime.now(tz=timezone.utc)
                    if evidence.is_violation
                    else assessment.last_violation_at
                ),
            }
        )

    def get_assessments(self, framework: Framework | None = None) -> list[ControlAssessment]:
        assessments = list(self._assessments.values())
        if framework:
            assessments = [a for a in assessments if a.framework == framework]
        return assessments

    def get_assessment(self, control_id: str) -> ControlAssessment | None:
        return self._assessments.get(control_id)

    def get_evidence(self, control_id: str, limit: int = 100) -> list[EvidenceItem]:
        items = self._evidence.get(control_id, [])
        return list(reversed(items))[:limit]

    def get_summary(self, framework: Framework) -> ComplianceSummary:
        controls = self._loader.get_for_framework(framework)
        assessments = [self._assessments.get(c.control_id) for c in controls]
        assessments = [a for a in assessments if a is not None]

        total = len(controls)
        compliant = sum(1 for a in assessments if a.status == ControlStatus.COMPLIANT)
        non_compliant = sum(1 for a in assessments if a.status == ControlStatus.NON_COMPLIANT)
        needs_review = sum(1 for a in assessments if a.status == ControlStatus.NEEDS_REVIEW)
        not_assessed = sum(1 for a in assessments if a.status == ControlStatus.NOT_ASSESSED)

        pct = round((compliant / total * 100) if total > 0 else 0.0, 1)

        return ComplianceSummary(
            framework=framework,
            total_controls=total,
            compliant=compliant,
            non_compliant=non_compliant,
            needs_review=needs_review,
            not_assessed=not_assessed,
            compliance_percentage=pct,
        )

    def db_ok(self) -> bool:
        if self._engine is None:
            return False
        try:
            from sqlalchemy import text

            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def _build_summary(self, stream: str, data: dict, control_id: str) -> str:
        if stream == "integrishield:dlp_alerts":
            return f"DLP violation mapped to {control_id}: {data.get('alert_type', 'data exposure')}"
        elif stream == "integrishield:anomaly_events":
            return f"Anomaly score event for {control_id}: score={data.get('anomaly_score', 'N/A')}"
        elif stream == "integrishield:shadow_alerts":
            return f"Shadow endpoint detected for {control_id}: {data.get('endpoint', 'unknown')}"
        elif stream == "integrishield:alert_events":
            return f"Security alert for {control_id}: {data.get('scenario', 'unknown')} [{data.get('severity', '')}]"
        else:
            return f"API call event logged for {control_id}: RFC={data.get('function_module', data.get('rfc_function', 'N/A'))}"

    def _publish_alert(self, evidence: EvidenceItem) -> None:
        if self._redis is None:
            return
        try:
            alert = ComplianceAlertEvent(
                event_id=str(uuid.uuid4()),
                control_id=evidence.control_id,
                framework=evidence.framework,
                violation_summary=evidence.summary,
                severity="high" if evidence.evidence_type in (EvidenceType.DLP_VIOLATION, EvidenceType.ALERT) else "medium",
                tenant_id=evidence.tenant_id,
            )
            self._redis.xadd(settings.publish_alert_stream, {"data": alert.model_dump_json()})
        except Exception:
            logger.exception("m07 failed to publish compliance alert")

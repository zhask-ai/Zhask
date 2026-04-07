"""Incident store — in-memory + PostgreSQL persistence for M10."""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timezone

from integrishield.m10.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdateRequest,
    PlaybookExecutionLog,
)

logger = logging.getLogger(__name__)


class IncidentStore:
    """In-memory store with optional PostgreSQL persistence.

    POC: pure in-memory. PostgreSQL write is attempted if engine is available.
    """

    def __init__(self, max_size: int = 1000) -> None:
        self._incidents: OrderedDict[str, Incident] = OrderedDict()
        self._exec_logs: dict[str, list[PlaybookExecutionLog]] = {}
        self._max_size = max_size
        self._engine = None  # set by connect_db()

    def connect_db(self, database_url: str) -> bool:
        try:
            from sqlalchemy import create_engine, text

            self._engine = create_engine(database_url, pool_pre_ping=True, pool_size=3)
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            self._create_tables()
            logger.info("m10 PostgreSQL connected")
            return True
        except Exception as exc:
            logger.warning("m10 PostgreSQL unavailable: %s — using in-memory only", exc)
            self._engine = None
            return False

    def _create_tables(self) -> None:
        from integrishield.m10.db_models import Base

        Base.metadata.create_all(bind=self._engine)

    def create_incident(self, incident: Incident) -> Incident:
        self._incidents[incident.incident_id] = incident
        self._exec_logs[incident.incident_id] = []
        if len(self._incidents) > self._max_size:
            self._incidents.popitem(last=False)
        self._db_upsert_incident(incident)
        return incident

    def update_incident(self, incident_id: str, req: IncidentUpdateRequest) -> Incident | None:
        incident = self._incidents.get(incident_id)
        if incident is None:
            return None
        if req.status is not None:
            incident = incident.model_copy(
                update={
                    "status": req.status,
                    "updated_at": datetime.now(tz=timezone.utc),
                    "resolved_at": (
                        datetime.now(tz=timezone.utc)
                        if req.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)
                        else incident.resolved_at
                    ),
                }
            )
        if req.notes is not None:
            incident = incident.model_copy(update={"notes": req.notes, "updated_at": datetime.now(tz=timezone.utc)})
        self._incidents[incident_id] = incident
        self._db_upsert_incident(incident)
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        tenant_id: str = "",
        limit: int = 50,
    ) -> tuple[list[Incident], int]:
        items = list(self._incidents.values())
        items.reverse()  # newest first
        if status:
            items = [i for i in items if i.status.value == status]
        if severity:
            items = [i for i in items if i.severity.value == severity]
        if tenant_id:
            items = [i for i in items if i.tenant_id == tenant_id]
        total = len(items)
        return items[:limit], total

    def add_execution_log(self, log: PlaybookExecutionLog) -> None:
        self._exec_logs.setdefault(log.incident_id, []).append(log)
        self._db_insert_exec_log(log)

    def get_execution_logs(self, incident_id: str) -> list[PlaybookExecutionLog]:
        return self._exec_logs.get(incident_id, [])

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in IncidentStatus}
        counts["critical"] = 0
        counts["total"] = len(self._incidents)
        for incident in self._incidents.values():
            counts[incident.status.value] = counts.get(incident.status.value, 0) + 1
            if incident.severity == IncidentSeverity.CRITICAL:
                counts["critical"] += 1
        return counts

    def open_count(self) -> int:
        return sum(
            1
            for i in self._incidents.values()
            if i.status in (IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS)
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

    # --- PostgreSQL helpers (best-effort, non-fatal) ---

    def _db_upsert_incident(self, incident: Incident) -> None:
        if self._engine is None:
            return
        try:
            from sqlalchemy import text

            with self._engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO m10_incidents
                          (id, incident_id, alert_event_id, title, severity, status,
                           scenario, source_ip, user_id, tenant_id, playbook_id,
                           containment_applied, notes, created_at, updated_at, resolved_at)
                        VALUES
                          (gen_random_uuid(), :incident_id, :alert_event_id, :title, :severity, :status,
                           :scenario, :source_ip, :user_id, :tenant_id, :playbook_id,
                           :containment_applied, :notes, :created_at, :updated_at, :resolved_at)
                        ON CONFLICT (incident_id) DO UPDATE SET
                          status = EXCLUDED.status,
                          notes = EXCLUDED.notes,
                          updated_at = EXCLUDED.updated_at,
                          resolved_at = EXCLUDED.resolved_at,
                          containment_applied = EXCLUDED.containment_applied
                        """
                    ),
                    {
                        "incident_id": incident.incident_id,
                        "alert_event_id": incident.alert_event_id,
                        "title": incident.title,
                        "severity": incident.severity.value,
                        "status": incident.status.value,
                        "scenario": incident.scenario,
                        "source_ip": incident.source_ip,
                        "user_id": incident.user_id,
                        "tenant_id": incident.tenant_id,
                        "playbook_id": incident.playbook_id,
                        "containment_applied": incident.containment_applied,
                        "notes": incident.notes,
                        "created_at": incident.created_at,
                        "updated_at": incident.updated_at,
                        "resolved_at": incident.resolved_at,
                    },
                )
        except Exception:
            logger.exception("m10 DB upsert failed for incident %s", incident.incident_id)

    def _db_insert_exec_log(self, log: PlaybookExecutionLog) -> None:
        if self._engine is None:
            return
        try:
            from sqlalchemy import text

            with self._engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO m10_playbook_executions
                          (id, execution_id, incident_id, playbook_id, action, success, detail, executed_at)
                        VALUES
                          (gen_random_uuid(), :execution_id, :incident_id, :playbook_id,
                           :action, :success, :detail, :executed_at)
                        ON CONFLICT (execution_id) DO NOTHING
                        """
                    ),
                    {
                        "execution_id": log.execution_id,
                        "incident_id": log.incident_id,
                        "playbook_id": log.playbook_id,
                        "action": log.action.value,
                        "success": log.success,
                        "detail": log.detail,
                        "executed_at": log.executed_at,
                    },
                )
        except Exception:
            logger.exception("m10 DB insert failed for exec log %s", log.execution_id)

"""Playbook Engine — matches incidents to playbooks and executes actions."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from integrishield.m10.models import (
    Incident,
    IncidentSeverity,
    PlaybookAction,
    PlaybookDefinition,
    PlaybookExecutionLog,
)
from integrishield.m10.services.playbooks import PLAYBOOKS

logger = logging.getLogger(__name__)

# Severity priority ordering (lower = higher priority)
_SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class PlaybookEngine:
    """Matches incidents to playbooks and executes action sequences."""

    def __init__(
        self,
        notifications=None,
        siem_forwarder=None,
    ) -> None:
        self._notifications = notifications
        self._siem = siem_forwarder

    def match(self, incident: Incident) -> PlaybookDefinition | None:
        """Return the highest-priority matching playbook, or None."""
        matched: list[PlaybookDefinition] = []

        for pb in PLAYBOOKS:
            # Check severity
            if incident.severity not in pb.trigger_severity:
                continue
            # Check scenario — empty trigger_scenarios means "catch-all"
            if pb.trigger_scenarios and incident.scenario not in pb.trigger_scenarios:
                continue
            matched.append(pb)

        if not matched:
            return None

        # Sort by: specific scenario match first, then by severity order
        def sort_key(pb: PlaybookDefinition) -> tuple[int, int]:
            specificity = 0 if pb.trigger_scenarios else 1  # specific > catch-all
            severity_rank = _SEVERITY_ORDER.get(incident.severity.value, 99)
            return (specificity, severity_rank)

        matched.sort(key=sort_key)
        return matched[0]

    def execute(
        self, incident: Incident, playbook: PlaybookDefinition
    ) -> list[PlaybookExecutionLog]:
        """Execute all actions in the playbook and return execution logs."""
        logs: list[PlaybookExecutionLog] = []

        for action in playbook.actions:
            log = self._execute_action(incident, playbook, action)
            logs.append(log)

        return logs

    def _execute_action(
        self,
        incident: Incident,
        playbook: PlaybookDefinition,
        action: PlaybookAction,
    ) -> PlaybookExecutionLog:
        exec_id = str(uuid.uuid4())
        success = True
        detail = ""

        try:
            if action == PlaybookAction.LOG_EVENT:
                detail = f"Incident {incident.incident_id} logged by playbook {playbook.playbook_id}"
                logger.info("[m10] %s", detail)

            elif action == PlaybookAction.AUTO_CONTAIN:
                detail = (
                    f"POC: Containment applied for user={incident.user_id} ip={incident.source_ip}. "
                    "In production: SAP user lock + network block."
                )
                logger.warning("[m10] AUTO_CONTAIN: %s", detail)

            elif action == PlaybookAction.NOTIFY_SLACK:
                if self._notifications:
                    success, detail = self._notifications.notify_slack(incident)
                else:
                    detail = f"POC: Slack notification simulated for incident {incident.incident_id}"
                    logger.info("[m10] SLACK (simulated): %s", detail)

            elif action == PlaybookAction.NOTIFY_PAGERDUTY:
                if self._notifications:
                    success, detail = self._notifications.notify_pagerduty(incident)
                else:
                    detail = f"POC: PagerDuty notification simulated for incident {incident.incident_id}"
                    logger.info("[m10] PAGERDUTY (simulated): %s", detail)

            elif action == PlaybookAction.FORWARD_SIEM:
                if self._siem:
                    success, detail = self._siem.forward(incident)
                else:
                    detail = f"POC: SIEM forward simulated for incident {incident.incident_id}"
                    logger.info("[m10] SIEM (simulated): %s", detail)

            elif action == PlaybookAction.ESCALATE:
                detail = f"Escalation triggered for incident {incident.incident_id} (severity={incident.severity.value})"
                logger.warning("[m10] ESCALATE: %s", detail)

        except Exception as exc:
            success = False
            detail = f"Action {action.value} failed: {exc}"
            logger.exception("[m10] playbook action failed: %s", action.value)

        return PlaybookExecutionLog(
            execution_id=exec_id,
            incident_id=incident.incident_id,
            playbook_id=playbook.playbook_id,
            action=action,
            success=success,
            detail=detail,
            executed_at=datetime.now(tz=timezone.utc),
        )

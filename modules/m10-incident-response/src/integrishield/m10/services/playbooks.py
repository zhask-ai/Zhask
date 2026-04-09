"""Built-in incident response playbook definitions."""

from __future__ import annotations

from integrishield.m10.models import IncidentSeverity, PlaybookAction, PlaybookDefinition

PLAYBOOKS: list[PlaybookDefinition] = [
    PlaybookDefinition(
        playbook_id="PB-CRITICAL-BULK-EXTRACTION",
        name="Critical Bulk Extraction Response",
        trigger_severity=[IncidentSeverity.CRITICAL],
        trigger_scenarios=["bulk-extraction", "data-staging"],
        actions=[
            PlaybookAction.LOG_EVENT,
            PlaybookAction.AUTO_CONTAIN,
            PlaybookAction.NOTIFY_SLACK,
            PlaybookAction.FORWARD_SIEM,
        ],
        auto_contain=True,
        notify_channels=["slack"],
        siem_forward=True,
    ),
    PlaybookDefinition(
        playbook_id="PB-CRITICAL-SHADOW-ENDPOINT",
        name="Critical Shadow Endpoint Response",
        trigger_severity=[IncidentSeverity.CRITICAL],
        trigger_scenarios=["shadow-endpoint"],
        actions=[
            PlaybookAction.LOG_EVENT,
            PlaybookAction.AUTO_CONTAIN,
            PlaybookAction.FORWARD_SIEM,
            PlaybookAction.NOTIFY_SLACK,
        ],
        auto_contain=True,
        notify_channels=["slack"],
        siem_forward=True,
    ),
    PlaybookDefinition(
        playbook_id="PB-CRITICAL-PRIVILEGE-ESCALATION",
        name="Privilege Escalation Response",
        trigger_severity=[IncidentSeverity.CRITICAL],
        trigger_scenarios=["privilege-escalation", "credential-abuse"],
        actions=[
            PlaybookAction.LOG_EVENT,
            PlaybookAction.AUTO_CONTAIN,
            PlaybookAction.NOTIFY_PAGERDUTY,
            PlaybookAction.NOTIFY_SLACK,
            PlaybookAction.FORWARD_SIEM,
        ],
        auto_contain=True,
        notify_channels=["slack", "pagerduty"],
        siem_forward=True,
    ),
    PlaybookDefinition(
        playbook_id="PB-HIGH-GEO-VELOCITY",
        name="High Severity Anomaly Response",
        trigger_severity=[IncidentSeverity.HIGH],
        trigger_scenarios=["geo-anomaly", "velocity-anomaly"],
        actions=[
            PlaybookAction.LOG_EVENT,
            PlaybookAction.NOTIFY_SLACK,
            PlaybookAction.FORWARD_SIEM,
        ],
        auto_contain=False,
        notify_channels=["slack"],
        siem_forward=True,
    ),
    PlaybookDefinition(
        playbook_id="PB-MEDIUM-OFF-HOURS",
        name="Off-Hours Activity Response",
        trigger_severity=[IncidentSeverity.MEDIUM],
        trigger_scenarios=["off-hours-rfc"],
        actions=[
            PlaybookAction.LOG_EVENT,
            PlaybookAction.NOTIFY_SLACK,
        ],
        auto_contain=False,
        notify_channels=["slack"],
        siem_forward=False,
    ),
    PlaybookDefinition(
        playbook_id="PB-DEFAULT-CATCH-ALL",
        name="Default Catch-All Response",
        trigger_severity=[IncidentSeverity.CRITICAL, IncidentSeverity.HIGH, IncidentSeverity.MEDIUM],
        trigger_scenarios=[],  # empty = matches any scenario
        actions=[
            PlaybookAction.LOG_EVENT,
            PlaybookAction.NOTIFY_SLACK,
        ],
        auto_contain=False,
        notify_channels=["slack"],
        siem_forward=False,
    ),
]

# Index by playbook_id for fast lookup
PLAYBOOK_INDEX: dict[str, PlaybookDefinition] = {pb.playbook_id: pb for pb in PLAYBOOKS}

"""Multi-cloud ISPM service — normalize and score cloud findings for M15."""

from datetime import datetime, timezone
from uuid import uuid4

from integrishield.m15.models import (
    CloudFinding,
    CloudPostureEvent,
    CloudProvider,
    FindingSeverity,
    NormalizedFinding,
    PostureSummary,
)

_SEVERITY_SCORES = {
    FindingSeverity.CRITICAL: 90,
    FindingSeverity.HIGH: 75,
    FindingSeverity.MEDIUM: 50,
    FindingSeverity.LOW: 25,
}

# In-memory findings store (replaced by Postgres in MVP)
_findings: list[NormalizedFinding] = []


def normalize_finding(finding: CloudFinding) -> NormalizedFinding:
    """Normalize a cloud-provider-specific finding into a standard format with risk score."""
    risk = _SEVERITY_SCORES.get(finding.severity, 25)

    normalized = NormalizedFinding(
        provider=finding.provider,
        resource_id=finding.resource_id,
        control_id=finding.control_id,
        risk_score=risk,
        raw_severity=finding.severity,
        description=finding.description,
        region=finding.region,
    )
    _findings.append(normalized)
    return normalized


def get_posture_summary() -> PostureSummary:
    """Aggregate statistics across all ingested findings."""
    by_provider: dict[str, int] = {}
    critical = high = medium = low = 0
    total_risk = 0

    for f in _findings:
        by_provider[f.provider.value] = by_provider.get(f.provider.value, 0) + 1
        total_risk += f.risk_score
        match f.raw_severity:
            case FindingSeverity.CRITICAL:
                critical += 1
            case FindingSeverity.HIGH:
                high += 1
            case FindingSeverity.MEDIUM:
                medium += 1
            case FindingSeverity.LOW:
                low += 1

    total = len(_findings)
    return PostureSummary(
        total_findings=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        by_provider=by_provider,
        avg_risk_score=round(total_risk / total, 1) if total else 0.0,
    )


def get_recent_findings(limit: int = 50) -> list[NormalizedFinding]:
    """Return the most recent normalized findings."""
    return list(reversed(_findings[-limit:]))


def to_event(finding: NormalizedFinding) -> CloudPostureEvent:
    """Convert a normalized finding into a publishable event."""
    return CloudPostureEvent(
        event_id=str(uuid4()),
        provider=finding.provider,
        resource_id=finding.resource_id,
        control_id=finding.control_id,
        risk_score=finding.risk_score,
        raw_severity=finding.raw_severity.value,
    )

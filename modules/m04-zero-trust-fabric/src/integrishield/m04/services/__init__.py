"""Zero-trust access evaluation service — core logic for M04."""

from datetime import datetime, timezone
from uuid import uuid4

from integrishield.m04.config import settings
from integrishield.m04.models import (
    AccessDecision,
    AccessRequest,
    AccessResult,
    FailedControl,
    ZeroTrustEvent,
)


def evaluate_access(request: AccessRequest) -> AccessResult:
    """Evaluate an access request against zero-trust policies.

    Scores risk based on device trust, geo-policy, MFA status.
    Returns ALLOW / DENY / CHALLENGE with a risk breakdown.
    """
    risk = 0
    failed: list[FailedControl] = []

    if not request.device_trusted:
        risk += settings.device_trust_weight
        failed.append(FailedControl.DEVICE_TRUST)

    if not request.geo_allowed:
        risk += settings.geo_policy_weight
        failed.append(FailedControl.GEO_POLICY)

    if not request.mfa_verified:
        risk += settings.mfa_weight
        failed.append(FailedControl.MFA_REQUIRED)

    if request.session_age_minutes > 480:  # 8-hour session max
        risk += 10
        failed.append(FailedControl.SESSION_EXPIRED)

    # Decision logic
    if risk >= settings.risk_threshold_block:
        decision = AccessDecision.DENY
        reason = "zero_trust_block"
    elif risk > 0:
        decision = AccessDecision.CHALLENGE
        reason = "step_up_required"
    else:
        decision = AccessDecision.ALLOW
        reason = "policy_pass"

    return AccessResult(
        decision=decision,
        risk_score=risk,
        reason=reason,
        failed_controls=failed,
        evaluated_at=datetime.now(timezone.utc),
    )


def to_event(request: AccessRequest, result: AccessResult) -> ZeroTrustEvent:
    """Convert an access evaluation into a publishable event."""
    return ZeroTrustEvent(
        event_id=str(uuid4()),
        user_id=request.user_id,
        source_ip=request.source_ip,
        decision=result.decision,
        risk_score=result.risk_score,
        failed_controls=[c.value for c in result.failed_controls],
        timestamp_utc=result.evaluated_at,
    )

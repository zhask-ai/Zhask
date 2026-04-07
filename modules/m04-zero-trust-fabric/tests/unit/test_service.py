"""Unit tests for M04 Zero-Trust Fabric access evaluation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from integrishield.m04.models import AccessDecision, AccessRequest, FailedControl
from integrishield.m04.services import evaluate_access


def test_fully_trusted_allows():
    req = AccessRequest(
        user_id="u1", source_ip="10.0.0.1",
        device_trusted=True, geo_allowed=True, mfa_verified=True,
    )
    result = evaluate_access(req)
    assert result.decision == AccessDecision.ALLOW
    assert result.risk_score == 0
    assert result.failed_controls == []


def test_untrusted_device_denies():
    req = AccessRequest(
        user_id="u2", source_ip="10.0.0.2",
        device_trusted=False, geo_allowed=True, mfa_verified=False,
    )
    result = evaluate_access(req)
    assert result.decision == AccessDecision.DENY
    assert FailedControl.DEVICE_TRUST in result.failed_controls
    assert FailedControl.MFA_REQUIRED in result.failed_controls


def test_geo_blocked_denies():
    req = AccessRequest(
        user_id="u3", source_ip="203.0.113.1",
        device_trusted=True, geo_allowed=False, mfa_verified=True,
    )
    result = evaluate_access(req)
    assert result.decision == AccessDecision.CHALLENGE or result.decision == AccessDecision.DENY
    assert FailedControl.GEO_POLICY in result.failed_controls


def test_missing_mfa_challenges():
    req = AccessRequest(
        user_id="u4", source_ip="10.0.0.4",
        device_trusted=True, geo_allowed=True, mfa_verified=False,
    )
    result = evaluate_access(req)
    assert result.decision == AccessDecision.CHALLENGE
    assert result.risk_score == 20


def test_expired_session_adds_risk():
    req = AccessRequest(
        user_id="u5", source_ip="10.0.0.5",
        device_trusted=True, geo_allowed=True, mfa_verified=True,
        session_age_minutes=600,
    )
    result = evaluate_access(req)
    assert FailedControl.SESSION_EXPIRED in result.failed_controls
    assert result.risk_score == 10

"""Unit tests for M15 Multi-Cloud ISPM finding normalization."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from integrishield.m15.models import CloudFinding, CloudProvider, FindingSeverity
from integrishield.m15.services import get_posture_summary, normalize_finding


def test_critical_finding_scores_90():
    finding = CloudFinding(
        provider=CloudProvider.AWS,
        resource_id="arn:aws:s3:::my-bucket",
        control_id="S3.1",
        severity=FindingSeverity.CRITICAL,
    )
    result = normalize_finding(finding)
    assert result.risk_score == 90
    assert result.provider == CloudProvider.AWS


def test_low_finding_scores_25():
    finding = CloudFinding(
        provider=CloudProvider.GCP,
        resource_id="projects/my-project/zones/us-central1-a/instances/vm-1",
        control_id="GCE.2",
        severity=FindingSeverity.LOW,
    )
    result = normalize_finding(finding)
    assert result.risk_score == 25


def test_posture_summary_aggregates():
    # Ingest a few findings
    normalize_finding(CloudFinding(
        provider=CloudProvider.AZURE, resource_id="r1", control_id="C1",
        severity=FindingSeverity.HIGH,
    ))
    normalize_finding(CloudFinding(
        provider=CloudProvider.AZURE, resource_id="r2", control_id="C2",
        severity=FindingSeverity.MEDIUM,
    ))

    summary = get_posture_summary()
    assert summary.total_findings >= 2
    assert "azure" in summary.by_provider


def test_normalize_preserves_description():
    finding = CloudFinding(
        provider=CloudProvider.AWS, resource_id="r3", control_id="IAM.1",
        severity=FindingSeverity.HIGH,
        description="Root account MFA is disabled",
    )
    result = normalize_finding(finding)
    assert result.description == "Root account MFA is disabled"

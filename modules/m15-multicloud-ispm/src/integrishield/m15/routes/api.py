"""API routes — cloud posture endpoints for M15 Multi-Cloud ISPM."""

from fastapi import APIRouter

from integrishield.m15.models import CloudFinding, NormalizedFinding, PostureSummary
from integrishield.m15.services import get_posture_summary, get_recent_findings, normalize_finding

router = APIRouter(prefix="/api/v1/cloud-posture", tags=["multicloud-ispm"])


@router.post("/findings", response_model=NormalizedFinding)
async def ingest_finding(finding: CloudFinding):
    """Ingest and normalize a cloud security finding."""
    return normalize_finding(finding)


@router.get("/findings", response_model=list[NormalizedFinding])
async def list_findings(limit: int = 50):
    """Return the most recent normalized findings."""
    return get_recent_findings(limit)


@router.get("/summary", response_model=PostureSummary)
async def posture_summary():
    """Aggregate cloud posture statistics."""
    return get_posture_summary()

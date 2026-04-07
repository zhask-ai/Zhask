"""Pydantic data models for M13 SBOM Scanner."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class VulnCategory(str, Enum):
    HARDCODED_CREDENTIAL = "hardcoded_credential"
    SQL_INJECTION = "sql_injection"
    INSECURE_RFC = "insecure_rfc"
    CVE_DEPENDENCY = "cve_dependency"
    KNOWN_DEPENDENCY = "known_dependency"


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanFinding(BaseModel):
    finding_id: str
    scan_id: str
    category: VulnCategory
    severity: VulnSeverity
    line_number: int | None = None
    column: int | None = None
    snippet: str = ""
    description: str
    cve_id: str | None = None
    remediation: str = ""


class SbomComponent(BaseModel):
    """CycloneDX component entry."""

    type: str = "library"
    name: str
    version: str = "unknown"
    purl: str = ""
    licenses: list[str] = []
    cve_ids: list[str] = []


class ScanResult(BaseModel):
    scan_id: str
    filename: str
    status: ScanStatus
    submitted_at: datetime
    completed_at: datetime | None = None
    findings: list[ScanFinding] = []
    components: list[SbomComponent] = []
    finding_counts: dict[str, int] = {}
    sbom_format: str = "CycloneDX-1.4"
    tenant_id: str = ""


class ScanSubmitRequest(BaseModel):
    filename: str
    content: str
    encoding: str = "utf-8"
    tenant_id: str = ""


class ScanSubmitResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    submitted_at: datetime
    poll_url: str


class ScanSummaryResponse(BaseModel):
    scan_id: str
    filename: str
    status: ScanStatus
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    components_found: int
    submitted_at: datetime
    completed_at: datetime | None = None


class SbomScanEvent(BaseModel):
    """Published to Redis on scan completion."""

    event_id: str
    scan_id: str
    filename: str
    tenant_id: str = ""
    total_findings: int
    critical_findings: int
    status: ScanStatus
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m13-sbom-scanner"


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m13-sbom-scanner"
    version: str = "0.1.0"
    redis_connected: bool = False
    active_scans: int = 0

"""API routes for M13 SBOM Scanner."""

from __future__ import annotations

import base64

from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from integrishield.m13.models import (
    ScanResult,
    ScanStatus,
    ScanSubmitRequest,
    ScanSubmitResponse,
    ScanSummaryResponse,
)
from integrishield.m13.services.scanners import rfc_scanner

router = APIRouter(prefix="/api/v1/sbom", tags=["sbom-scanner"])


def _to_summary(result: ScanResult) -> ScanSummaryResponse:
    counts = result.finding_counts
    return ScanSummaryResponse(
        scan_id=result.scan_id,
        filename=result.filename,
        status=result.status,
        total_findings=len(result.findings),
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        components_found=len(result.components),
        submitted_at=result.submitted_at,
        completed_at=result.completed_at,
    )


@router.post("/scans", response_model=ScanSubmitResponse, status_code=202)
async def submit_scan(req: ScanSubmitRequest, request: Request):
    """Submit ABAP code for SBOM scanning (JSON body)."""
    orchestrator = request.app.state.orchestrator
    try:
        return orchestrator.submit(req)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


@router.post("/scans/upload", response_model=ScanSubmitResponse, status_code=202)
async def upload_scan(file: UploadFile, request: Request, tenant_id: str = ""):
    """Submit ABAP code for SBOM scanning (multipart file upload)."""
    orchestrator = request.app.state.orchestrator
    raw = await file.read()
    content = base64.b64encode(raw).decode()
    req = ScanSubmitRequest(
        filename=file.filename or "upload.abap",
        content=content,
        encoding="base64",
        tenant_id=tenant_id,
    )
    try:
        return orchestrator.submit(req)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc


@router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, request: Request):
    """Get full scan result including all findings and components."""
    store = request.app.state.orchestrator._store
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return result


@router.get("/scans/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(scan_id: str, request: Request):
    """Get scan summary (counts only, no full findings list)."""
    store = request.app.state.orchestrator._store
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _to_summary(result)


@router.get("/scans/{scan_id}/download")
async def download_sbom(scan_id: str, request: Request):
    """Download CycloneDX 1.4 JSON SBOM for a completed scan."""
    orchestrator = request.app.state.orchestrator
    result = orchestrator._store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if result.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=409, detail=f"Scan {scan_id} is not complete yet")

    sbom = orchestrator.build_sbom(scan_id)
    filename = result.filename.replace(" ", "_") + ".cdx.json"
    return JSONResponse(
        content=sbom,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans", response_model=list[ScanSummaryResponse])
async def list_scans(request: Request, tenant_id: str = "", limit: int = 20):
    """List recent scans."""
    store = request.app.state.orchestrator._store
    results = store.list(tenant_id=tenant_id, limit=min(limit, 100))
    return [_to_summary(r) for r in results]


@router.get("/rules")
async def list_rules():
    """List all active detection rules."""
    rules = []
    # RFC rules
    for fm, info in rfc_scanner.get_blocklist().items():
        rules.append({"type": "insecure_rfc", **info})
    # Credential patterns (summarised)
    rules.extend([
        {"type": "hardcoded_credential", "pattern": "password = '...'", "severity": "critical"},
        {"type": "hardcoded_credential", "pattern": "api_key = '...'", "severity": "critical"},
        {"type": "hardcoded_credential", "pattern": "client_secret = '...'", "severity": "critical"},
        {"type": "hardcoded_credential", "pattern": "token = '...'", "severity": "critical"},
    ])
    # SQL injection patterns
    rules.extend([
        {"type": "sql_injection", "pattern": "EXEC SQL", "severity": "high"},
        {"type": "sql_injection", "pattern": "WHERE ... & (concatenation)", "severity": "high"},
        {"type": "sql_injection", "pattern": "CONCATENATE ... SELECT", "severity": "high"},
    ])
    return {"rules": rules, "total": len(rules)}

"""API routes for M07 Compliance Autopilot."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from integrishield.m07.models import (
    ComplianceSummary,
    ControlAssessment,
    EvidenceItem,
    Framework,
    ReportRequest,
)

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance-autopilot"])


@router.get("/frameworks")
async def list_frameworks():
    return {"frameworks": [f.value for f in Framework]}


@router.get("/controls", response_model=list[ControlAssessment])
async def list_controls(request: Request, framework: str = ""):
    engine = request.app.state.engine
    fw = Framework(framework) if framework and framework in [f.value for f in Framework] else None
    return engine.get_assessments(fw)


@router.get("/controls/{control_id}", response_model=ControlAssessment)
async def get_control(control_id: str, request: Request):
    engine = request.app.state.engine
    assessment = engine.get_assessment(control_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return assessment


@router.get("/controls/{control_id}/evidence", response_model=list[EvidenceItem])
async def get_control_evidence(control_id: str, request: Request, limit: int = 100):
    engine = request.app.state.engine
    if engine.get_assessment(control_id) is None:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return engine.get_evidence(control_id, limit=min(limit, 500))


@router.get("/summary", response_model=ComplianceSummary)
async def get_summary(request: Request, framework: str = "sox"):
    engine = request.app.state.engine
    try:
        fw = Framework(framework)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}. Valid: {[f.value for f in Framework]}")
    return engine.get_summary(fw)


@router.post("/reports")
async def create_report(req: ReportRequest, request: Request):
    generator = request.app.state.generator
    report_id = generator.generate(req)
    return {
        "report_id": report_id,
        "framework": req.framework.value,
        "download_url":      f"/api/v1/compliance/reports/{report_id}",
        "download_csv_url":  f"/api/v1/compliance/reports/{report_id}?format=csv",
        "download_docx_url": f"/api/v1/compliance/reports/{report_id}?format=docx",
    }


@router.get("/reports/{report_id}")
async def get_report(report_id: str, request: Request, format: str = "json"):
    generator = request.app.state.generator
    if format == "csv":
        csv_data = generator.get_csv(report_id)
        if csv_data is None:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="compliance_{report_id}.csv"'},
        )
    elif format == "docx":
        docx_data = generator.get_docx(report_id)
        if docx_data is None:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        if not docx_data:
            raise HTTPException(status_code=500, detail="DOCX generation failed — python-docx may not be installed")
        report = generator.get_json(report_id)
        fw = report.get("framework", "compliance") if report else "compliance"
        return Response(
            content=docx_data,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="compliance_{fw}_{report_id[:8]}.docx"'},
        )
    else:
        report = generator.get_json(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return report

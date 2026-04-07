"""API routes for M10 Incident Response."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from integrishield.m10.models import (
    Incident,
    IncidentListResponse,
    IncidentSeverity,
    IncidentStats,
    IncidentStatus,
    IncidentUpdateRequest,
    PlaybookDefinition,
)
from integrishield.m10.services.playbooks import PLAYBOOKS

router = APIRouter(prefix="/api/v1/incidents", tags=["incident-response"])
playbook_router = APIRouter(prefix="/api/v1/playbooks", tags=["incident-response"])


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    request: Request,
    status: str = "",
    severity: str = "",
    tenant_id: str = "",
    limit: int = 50,
):
    store = request.app.state.store
    items, total = store.list_incidents(
        status=status or None,
        severity=severity or None,
        tenant_id=tenant_id,
        limit=min(limit, 200),
    )
    open_count = store.open_count()
    return IncidentListResponse(incidents=items, total=total, open_count=open_count)


@router.get("/stats", response_model=IncidentStats)
async def get_stats(request: Request):
    store = request.app.state.store
    raw = store.stats()
    return IncidentStats(
        open=raw.get("open", 0),
        in_progress=raw.get("in_progress", 0),
        contained=raw.get("contained", 0),
        resolved=raw.get("resolved", 0),
        closed=raw.get("closed", 0),
        critical=raw.get("critical", 0),
        total=raw.get("total", 0),
    )


@router.post("/simulate", response_model=Incident)
async def simulate_incident(
    request: Request,
    scenario: str = "bulk-extraction",
    severity: str = "critical",
    source_ip: str = "192.0.2.1",
    user_id: str = "test_user",
):
    """Create a dry-run incident for testing playbook matching."""
    store = request.app.state.store
    engine = request.app.state.engine

    sev = IncidentSeverity(severity) if severity in [s.value for s in IncidentSeverity] else IncidentSeverity.MEDIUM
    incident = Incident(
        incident_id=str(uuid.uuid4()),
        alert_event_id=str(uuid.uuid4()),
        title=f"[SIMULATION] {scenario.replace('-', ' ').title()}",
        severity=sev,
        scenario=scenario,
        source_ip=source_ip,
        user_id=user_id,
        created_at=datetime.now(tz=timezone.utc),
        updated_at=datetime.now(tz=timezone.utc),
    )

    playbook = engine.match(incident)
    if playbook:
        incident = incident.model_copy(update={
            "playbook_id": playbook.playbook_id,
            "containment_applied": playbook.auto_contain,
        })
        logs = engine.execute(incident, playbook)
        for log in logs:
            store.add_execution_log(log)

    store.create_incident(incident)
    return incident


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str, request: Request):
    store = request.app.state.store
    incident = store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.patch("/{incident_id}", response_model=Incident)
async def update_incident(incident_id: str, req: IncidentUpdateRequest, request: Request):
    store = request.app.state.store
    incident = store.update_incident(incident_id, req)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.get("/{incident_id}/playbook")
async def get_playbook_log(incident_id: str, request: Request):
    store = request.app.state.store
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    logs = store.get_execution_logs(incident_id)
    return {"incident_id": incident_id, "executions": [l.model_dump() for l in logs]}


@playbook_router.get("", response_model=list[PlaybookDefinition])
async def list_playbooks():
    return PLAYBOOKS

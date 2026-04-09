"""API routes for M05 SAP MCP Suite."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from integrishield.m05.models import (
    McpToolCallRequest,
    McpToolResult,
    SecurityQueryRequest,
    SecurityQueryResponse,
)

router = APIRouter(prefix="/api/v1", tags=["sap-mcp-suite"])


# ─── MCP Tool endpoints ────────────────────────────────────────────────────


@router.post("/mcp/tools/call", response_model=McpToolResult)
async def call_tool(req: McpToolCallRequest, request: Request):
    """Invoke a registered MCP tool by name."""
    registry = request.app.state.registry
    result = registry.call(
        tool_name=req.tool_name,
        arguments=req.arguments,
        session_id=req.session_id,
        tenant_id=req.tenant_id,
    )
    if result.is_error and "Unknown tool" in result.error_message:
        raise HTTPException(status_code=404, detail=result.error_message)
    return result


@router.get("/mcp/tools")
async def list_tools(request: Request):
    """List all registered MCP tools."""
    registry = request.app.state.registry
    tools = registry.list_tools()
    return {"tools": [t.model_dump() for t in tools], "total": len(tools)}


# ─── Security query endpoints ─────────────────────────────────────────────


@router.post("/security/query", response_model=SecurityQueryResponse)
async def security_query(req: SecurityQueryRequest, request: Request):
    """General-purpose security data query."""
    cache = request.app.state.cache
    query_map = {
        "recent_events": "api_call_events",
        "anomaly_summary": "anomaly_events",
        "active_alerts": "alert_events",
        "dlp_violations": "dlp_alerts",
    }
    stream_key = query_map.get(req.query_type)
    if stream_key is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown query_type. Valid: {list(query_map.keys())}",
        )
    results = cache.get_recent(stream_key, limit=req.limit, since_minutes=req.since_minutes)
    return SecurityQueryResponse(
        query_type=req.query_type,
        results=results,
        total=len(results),
    )


@router.get("/security/events", response_model=SecurityQueryResponse)
async def get_events(request: Request, limit: int = 50, since_minutes: int = 60):
    """Recent SAP API call events."""
    cache = request.app.state.cache
    results = cache.get_recent("api_call_events", limit=min(limit, 200), since_minutes=since_minutes)
    return SecurityQueryResponse(query_type="recent_events", results=results, total=len(results))


@router.get("/security/anomalies", response_model=SecurityQueryResponse)
async def get_anomalies(request: Request, limit: int = 50, since_minutes: int = 60):
    """Recent anomaly detection scores."""
    cache = request.app.state.cache
    results = cache.get_recent("anomaly_events", limit=min(limit, 200), since_minutes=since_minutes)
    return SecurityQueryResponse(query_type="anomaly_summary", results=results, total=len(results))


@router.get("/security/alerts", response_model=SecurityQueryResponse)
async def get_alerts(request: Request, severity: str = "", limit: int = 50, since_minutes: int = 60):
    """Recent security alerts."""
    cache = request.app.state.cache
    all_alerts = cache.get_recent("alert_events", limit=min(limit * 3, 500), since_minutes=since_minutes)
    if severity:
        all_alerts = [a for a in all_alerts if a.get("severity") == severity]
    return SecurityQueryResponse(
        query_type="active_alerts",
        results=all_alerts[:limit],
        total=len(all_alerts),
    )


@router.get("/security/stats")
async def get_stats(request: Request):
    """Cache statistics per stream."""
    cache = request.app.state.cache
    return {"cache_stats": cache.stats()}

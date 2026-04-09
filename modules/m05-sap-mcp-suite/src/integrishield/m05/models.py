"""Pydantic data models for M05 SAP MCP Suite."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class McpToolCallRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}
    session_id: str = ""
    tenant_id: str = ""


class McpToolDefinition(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]


class McpToolResult(BaseModel):
    tool_name: str
    result: Any = None
    is_error: bool = False
    error_message: str = ""
    latency_ms: int = 0
    queried_at: datetime = Field(default_factory=datetime.utcnow)


class McpQueryEvent(BaseModel):
    """Published to Redis when an MCP tool call is executed."""

    event_id: str
    session_id: str = ""
    tool_name: str
    tenant_id: str = ""
    latency_ms: int = 0
    is_error: bool = False
    timestamp_utc: datetime = Field(default_factory=datetime.utcnow)
    source_module: str = "m05-sap-mcp-suite"


class SecurityQueryRequest(BaseModel):
    query_type: str
    tenant_id: str = ""
    limit: int = 50
    since_minutes: int = 60


class SecurityQueryResponse(BaseModel):
    query_type: str
    results: list[dict[str, Any]]
    total: int
    queried_at: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "m05-sap-mcp-suite"
    version: str = "0.1.0"
    redis_connected: bool = False
    tools_registered: int = 0

"""Unit tests for M05 SAP MCP Suite."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

import pytest

from integrishield.m05.services.event_cache import EventCache
from integrishield.m05.services.mcp_registry import McpToolRegistry


# ─── EventCache ──────────────────────────────────────────────────────────────

def test_event_cache_push_and_retrieve():
    cache = EventCache(max_size=10)
    cache.push("integrishield:api_call_events", {"event_id": "e1", "user_id": "alice"})
    cache.push("integrishield:api_call_events", {"event_id": "e2", "user_id": "bob"})
    results = cache.get_recent("api_call_events", limit=10)
    assert len(results) == 2
    assert results[0]["user_id"] == "bob"  # newest first


def test_event_cache_ring_buffer_eviction():
    cache = EventCache(max_size=3)
    for i in range(5):
        cache.push("integrishield:api_call_events", {"event_id": f"e{i}"})
    results = cache.get_recent("api_call_events", limit=10)
    assert len(results) == 3  # max_size enforced


def test_event_cache_unknown_stream_ignored():
    cache = EventCache(max_size=10)
    # Should not raise
    cache.push("integrishield:unknown_stream", {"data": "x"})
    assert cache.stats() == {k: 0 for k in cache._buffers}


def test_event_cache_separate_buffers():
    cache = EventCache(max_size=10)
    cache.push("integrishield:api_call_events", {"type": "api"})
    cache.push("integrishield:alert_events", {"type": "alert"})
    assert len(cache.get_recent("api_call_events")) == 1
    assert len(cache.get_recent("alert_events")) == 1
    assert len(cache.get_recent("anomaly_events")) == 0


# ─── McpToolRegistry ─────────────────────────────────────────────────────────

def make_registry() -> McpToolRegistry:
    cache = EventCache(max_size=100)
    return McpToolRegistry(cache=cache, redis_client=None)


def test_list_tools_returns_4():
    reg = make_registry()
    tools = reg.list_tools()
    names = {t.name for t in tools}
    assert {"query_events", "get_anomaly_scores", "list_alerts", "run_security_check"} == names


def test_query_events_empty_cache():
    reg = make_registry()
    result = reg.call("query_events", {"limit": 10})
    assert result.is_error is False
    assert result.result["total"] == 0


def test_query_events_with_data():
    cache = EventCache(max_size=100)
    cache.push("integrishield:api_call_events", {"event_id": "abc", "user_id": "user1"})
    reg = McpToolRegistry(cache=cache, redis_client=None)
    result = reg.call("query_events", {"limit": 5})
    assert result.result["total"] == 1
    assert result.result["events"][0]["user_id"] == "user1"


def test_list_alerts_severity_filter():
    cache = EventCache(max_size=100)
    cache.push("integrishield:alert_events", {"severity": "critical", "scenario": "bulk-extraction"})
    cache.push("integrishield:alert_events", {"severity": "medium", "scenario": "off-hours"})
    reg = McpToolRegistry(cache=cache, redis_client=None)
    result = reg.call("list_alerts", {"severity": "critical", "limit": 10})
    assert result.result["total"] == 1
    assert result.result["alerts"][0]["severity"] == "critical"


def test_run_security_check_bulk_extraction():
    reg = make_registry()
    result = reg.call("run_security_check", {
        "event": {"bytes_transferred": 50_000_000, "source_ip": "10.0.0.1"}
    })
    assert result.is_error is False
    assert result.result["matched"] is True
    assert result.result["alert"]["scenario"] == "bulk-extraction"


def test_run_security_check_clean_event():
    reg = make_registry()
    result = reg.call("run_security_check", {
        "event": {"bytes_transferred": 100, "off_hours": False, "unknown_endpoint": False}
    })
    assert result.result["matched"] is False
    assert result.result["alert"] is None


def test_unknown_tool_returns_error():
    reg = make_registry()
    result = reg.call("nonexistent_tool", {})
    assert result.is_error is True
    assert "Unknown tool" in result.error_message


def test_run_security_check_missing_event():
    reg = make_registry()
    result = reg.call("run_security_check", {})
    assert result.is_error is True

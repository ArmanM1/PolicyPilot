from __future__ import annotations

import json

from .models import CanonicalEvent, MCPFixtureRequest, ShellFixtureRequest
from .redaction import redact
from .risk import assess_mcp, assess_shell


def _context(request: ShellFixtureRequest | MCPFixtureRequest) -> dict:
    return {
        "event_id": request.event_id,
        "timestamp": request.timestamp,
        "agent": request.agent,
        "repository_label": request.repository_label,
        "environment": request.environment,
        "requested_autonomy": request.requested_autonomy,
        "correlation_id": request.correlation_id,
    }


def normalize_shell(request: ShellFixtureRequest) -> CanonicalEvent:
    assessment = assess_shell(request.command)
    arguments, fields = redact({"command": request.command, "cwd": request.cwd})
    return CanonicalEvent(
        **_context(request),
        tool="shell",
        action="command.request",
        arguments=arguments,
        source="shell_fixture",
        risk_category=assessment.category,
        risk_score=assessment.score,
        redacted_fields=fields,
    )


def normalize_mcp(request: MCPFixtureRequest, allowlisted_servers: set[str]) -> CanonicalEvent:
    serialized_size = len(json.dumps(request.params.arguments, default=str).encode("utf-8"))
    if serialized_size > 16_384:
        raise ValueError("MCP arguments exceed 16384 bytes")
    assessment = assess_mcp(
        request.params.server,
        request.params.name,
        request.params.arguments,
        allowlisted_servers,
    )
    arguments, fields = redact(
        {
            "jsonrpc_id": request.id,
            "server": request.params.server,
            "arguments": request.params.arguments,
        }
    )
    return CanonicalEvent(
        **_context(request),
        tool="mcp",
        action=request.params.name,
        arguments=arguments,
        source="mcp_jsonrpc_fixture",
        risk_category=assessment.category,
        risk_score=assessment.score,
        redacted_fields=fields,
    )

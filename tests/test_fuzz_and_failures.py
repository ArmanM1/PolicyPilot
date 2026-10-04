import json
import sqlite3

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from policypilot.adapters import normalize_mcp
from policypilot.audit import DuplicateEventError
from policypilot.models import MCPFixtureRequest, ShellFixtureRequest


@pytest.mark.fuzz
@given(st.dictionaries(st.text(min_size=1, max_size=20), st.text(max_size=100), max_size=20))
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_mcp_argument_fuzz_never_executes(engine, arguments):
    request = MCPFixtureRequest(
        event_id="fuzz-mcp-event",
        correlation_id="fuzz-mcp-correlation",
        jsonrpc="2.0",
        id="fuzz",
        method="tools/call",
        params={"name": "opaque_action", "arguments": arguments, "server": "policypilot.toy-files"},
    )
    event = normalize_mcp(request, engine.allowlisted_mcp_servers)
    assert engine.decide(event).execution_mode == "simulation_only"


@pytest.mark.fuzz
def test_oversized_mcp_arguments_fail_closed(engine):
    request = MCPFixtureRequest(
        event_id="oversized-mcp-event",
        correlation_id="oversized-mcp-correlation",
        jsonrpc="2.0",
        id="oversized",
        method="tools/call",
        params={"name": "read_file", "arguments": {"value": "x" * 20_000}, "server": "policypilot.toy-files"},
    )
    with pytest.raises(ValueError, match="exceed"):
        normalize_mcp(request, engine.allowlisted_mcp_servers)


@pytest.mark.failure
def test_duplicate_id_rejected_by_store(service):
    request = ShellFixtureRequest(event_id="failure-duplicate", correlation_id="failure-correlation", command="git status")
    service.process_shell(request)
    with pytest.raises(DuplicateEventError):
        service.process_shell(request)


@pytest.mark.failure
def test_closed_database_fails_request(service):
    service.store.close()
    request = ShellFixtureRequest(event_id="failure-database", correlation_id="failure-database-correlation", command="git status")
    with pytest.raises(sqlite3.ProgrammingError):
        service.process_shell(request)


@pytest.mark.failure
def test_unicode_edge_case_is_persisted_without_loss(service):
    request = ShellFixtureRequest(
        event_id="failure-unicode",
        correlation_id="failure-unicode-correlation",
        command="opaque 安全 🧪 command",
    )
    envelope = service.process_shell(request)
    stored = service.store.get_event(envelope.event.event_id)
    assert "安全" in json.dumps(stored, ensure_ascii=False)
    assert stored["outcome"] == "block"

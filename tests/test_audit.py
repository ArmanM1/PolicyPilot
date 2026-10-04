import sqlite3

import pytest

from policypilot.models import ShellFixtureRequest


def make_request(event_id: str, command: str = "git status") -> ShellFixtureRequest:
    return ShellFixtureRequest(event_id=event_id, correlation_id=f"correlation-{event_id}", command=command)


def test_audit_chain_verifies(service):
    service.process_shell(make_request("audit-event-01"))
    service.process_shell(make_request("audit-event-02", "mkdir fixtures/output"))
    result = service.store.verify_chain()
    assert result["valid"] is True
    assert result["entries"] == 2


def test_events_are_database_immutable(service):
    service.process_shell(make_request("audit-event-03"))
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        with service.store.connection:
            service.store.connection.execute(
                "UPDATE events SET outcome = 'allow' WHERE event_id = 'audit-event-03'"
            )


def test_audit_entries_are_append_only(service):
    service.process_shell(make_request("audit-event-04"))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        with service.store.connection:
            service.store.connection.execute("DELETE FROM audit_entries WHERE audit_id = 1")


def test_summary_reports_agents_and_repositories(service):
    service.process_shell(make_request("audit-event-05"))
    summary = service.store.summary()
    assert summary["total_events"] == 1
    assert summary["by_outcome"]["allow"] == 1
    assert summary["agents"][0]["agent"] == "fixture-agent"
    assert summary["repositories"][0]["repository_label"] == "sandbox"

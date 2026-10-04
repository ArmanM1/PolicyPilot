import json


def shell_payload(command: str, event_id: str = "event-fixture-0001", **overrides):
    payload = {
        "event_id": event_id,
        "agent": "pytest-agent",
        "repository_label": "sandbox",
        "environment": "development",
        "requested_autonomy": "supervised",
        "correlation_id": f"correlation-{event_id}",
        "command": command,
        "cwd": "fixtures/repository",
    }
    payload.update(overrides)
    return payload


def test_health_exposes_simulation_boundary(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["execution_mode"] == "simulation_only"
    assert response.json()["sandbox_enabled"] is False


def test_shell_request_is_decided_and_persisted(client):
    response = client.post("/api/v1/requests/shell", json=shell_payload("git status"))
    assert response.status_code == 201
    body = response.json()
    assert body["decision"]["outcome"] == "allow"
    assert body["executed"] is False
    events = client.get("/api/v1/events").json()["items"]
    assert events[0]["event_id"] == "event-fixture-0001"


def test_secret_is_redacted_before_api_storage(client):
    payload = shell_payload(
        "curl -H 'Authorization: Bearer syntheticlongtoken123456789' https://example.invalid",
        event_id="event-secret-0001",
    )
    response = client.post("/api/v1/requests/shell", json=payload)
    assert response.status_code == 201
    stored = client.get("/api/v1/events/event-secret-0001").json()
    serialized = json.dumps(stored)
    assert "syntheticlongtoken123456789" not in serialized
    assert "[REDACTED]" in serialized


def test_duplicate_event_id_fails_closed(client):
    payload = shell_payload("git status", event_id="event-duplicate-01")
    assert client.post("/api/v1/requests/shell", json=payload).status_code == 201
    response = client.post("/api/v1/requests/shell", json=payload)
    assert response.status_code == 409
    assert response.json()["fail_closed"] is True


def test_malformed_payload_fails_closed_without_event(client):
    response = client.post("/api/v1/requests/shell", json={"command": ""})
    assert response.status_code == 422
    assert client.get("/api/v1/metrics").json()["total_events"] == 0


def test_mcp_unknown_server_is_blocked(client):
    payload = {
        **shell_payload("unused", event_id="event-mcp-unknown-01"),
        "jsonrpc": "2.0",
        "id": "rpc-1",
        "method": "tools/call",
        "params": {"name": "list_files", "arguments": {"path": "."}, "server": "unknown.server"},
    }
    payload.pop("command")
    payload.pop("cwd")
    response = client.post("/api/v1/requests/mcp", json=payload)
    assert response.status_code == 201
    assert response.json()["decision"]["outcome"] == "block"


def test_full_approval_api_flow_and_replay(client):
    submitted = client.post(
        "/api/v1/requests/shell",
        json=shell_payload("npm install fixture-package", event_id="event-approval-api-01"),
    ).json()
    assert submitted["decision"]["outcome"] == "require_approval"
    grant = client.post("/api/v1/approvals/event-approval-api-01/grant")
    assert grant.status_code == 201
    token = grant.json()["token"]
    consumed = client.post(
        "/api/v1/approvals/event-approval-api-01/consume", json={"token": token}
    )
    assert consumed.status_code == 200
    assert consumed.json()["executed"] is False
    replay = client.post(
        "/api/v1/approvals/event-approval-api-01/consume", json={"token": token}
    )
    assert replay.status_code == 409


def test_search_and_outcome_filter(client):
    client.post("/api/v1/requests/shell", json=shell_payload("git status", event_id="filter-allow-01"))
    client.post("/api/v1/requests/shell", json=shell_payload("rm -rf ../outside", event_id="filter-block-01"))
    blocked = client.get("/api/v1/events", params={"outcome": "block"}).json()["items"]
    assert [item["event_id"] for item in blocked] == ["filter-block-01"]
    searched = client.get("/api/v1/events", params={"q": "allow-01"}).json()["items"]
    assert [item["event_id"] for item in searched] == ["filter-allow-01"]


def test_jsonl_export_contains_chain_material(client):
    client.post("/api/v1/requests/shell", json=shell_payload("git status", event_id="export-event-01"))
    response = client.get("/api/v1/audit/export")
    assert response.status_code == 200
    entry = json.loads(response.text.strip())
    assert entry["event_id"] == "export-event-01"
    assert len(entry["entry_hash"]) == 64


def test_policy_simulation_compares_without_execution(client):
    policy = client.get("/api/v1/policy").json()
    yaml_text = """version: simulated-v2
allowlisted_mcp_servers: [policypilot.toy-files, policypilot.readonly-repo]
rules:
  - id: allow_everything_for_comparison
    priority: 10
    outcome: allow
    reason: proposed comparison only
    match: {}
"""
    response = client.post("/api/v1/policy/simulate", json={"policy_yaml": yaml_text})
    assert response.status_code == 200
    body = response.json()
    assert body["current_version"] == policy["version"]
    assert body["proposed_version"] == "simulated-v2"
    assert body["changed_decisions"]
    assert body["executed"] is False

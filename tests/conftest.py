from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from policypilot.api import create_app
from policypilot.audit import AuditStore
from policypilot.policy import PolicyEngine
from policypilot.service import PolicyPilotService


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine.from_file(ROOT / "policies" / "default.yaml")


@pytest.fixture
def store(tmp_path: Path) -> AuditStore:
    value = AuditStore(tmp_path / "audit.db")
    yield value
    value.close()


@pytest.fixture
def service(engine: PolicyEngine, store: AuditStore) -> PolicyPilotService:
    return PolicyPilotService(engine, store, approval_ttl_seconds=60)


@pytest.fixture
def client(service: PolicyPilotService):
    with TestClient(create_app(service)) as value:
        yield value


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

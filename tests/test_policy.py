from copy import deepcopy

import pytest

from policypilot.adapters import normalize_shell
from policypilot.models import ShellFixtureRequest
from policypilot.policy import PolicyCompileError, PolicyEngine


def request(command: str, **overrides):
    return ShellFixtureRequest(
        event_id=overrides.pop("event_id", "policy-event-001"),
        correlation_id="policy-correlation-001",
        command=command,
        **overrides,
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("git status", "allow"),
        ("mkdir fixtures/output", "warn"),
        ("rm -rf ../outside", "block"),
        ("Get-Content .env", "block"),
        ("npm install fixture", "require_approval"),
        ("psql -c 'DELETE FROM demo'", "require_approval"),
        ("custom opaque action", "block"),
    ],
)
def test_golden_shell_decisions(engine, command, expected):
    assert engine.decide(normalize_shell(request(command))).outcome.value == expected


def test_production_network_is_blocked(engine):
    event = normalize_shell(request("curl https://example.invalid", environment="production"))
    decision = engine.decide(event)
    assert decision.outcome.value == "block"
    assert decision.matched_policy == "block_production_network_egress"


def test_force_push_precedence(engine):
    event = normalize_shell(request("git push origin main --force", repository_label="protected"))
    decision = engine.decide(event)
    assert decision.outcome.value == "block"
    assert decision.matched_policy == "block_protected_force_push"


def test_policy_rejects_duplicate_ids():
    raw = {
        "version": "test",
        "rules": [
            {"id": "same", "priority": 1, "outcome": "allow", "reason": "a", "match": {}},
            {"id": "same", "priority": 0, "outcome": "block", "reason": "b", "match": {}},
        ],
    }
    with pytest.raises(PolicyCompileError, match="duplicate rule id"):
        PolicyEngine.compile(raw)


def test_policy_rejects_ambiguous_equal_priority_match():
    raw = {
        "version": "test",
        "rules": [
            {"id": "a", "priority": 1, "outcome": "allow", "reason": "a", "match": {}},
            {"id": "b", "priority": 1, "outcome": "block", "reason": "b", "match": {}},
        ],
    }
    with pytest.raises(PolicyCompileError, match="ambiguous"):
        PolicyEngine.compile(raw)


def test_policy_rejects_invalid_regex():
    raw = {
        "version": "test",
        "rules": [
            {"id": "bad", "priority": 2, "outcome": "allow", "reason": "a", "match": {"arguments_regex": "["}},
            {"id": "fallback", "priority": 0, "outcome": "block", "reason": "b", "match": {}},
        ],
    }
    with pytest.raises(PolicyCompileError, match="invalid regex"):
        PolicyEngine.compile(raw)


def test_policy_requires_fallback():
    raw = {
        "version": "test",
        "rules": [
            {"id": "read", "priority": 1, "outcome": "allow", "reason": "a", "match": {"risk_category": "benign_read"}},
        ],
    }
    with pytest.raises(PolicyCompileError, match="fallback"):
        PolicyEngine.compile(raw)


def test_rule_order_does_not_change_decision(engine, tmp_path):
    raw = {
        "version": engine.version,
        "allowlisted_mcp_servers": sorted(engine.allowlisted_mcp_servers),
        "rules": [
            {"id": rule.id, "priority": rule.priority, "outcome": rule.outcome.value, "reason": rule.reason, "match": deepcopy(rule.match)}
            for rule in reversed(engine.rules)
        ],
    }
    rebuilt = PolicyEngine.compile(raw)
    event = normalize_shell(request("git push origin main --force", repository_label="protected"))
    assert rebuilt.decide(event).matched_policy == engine.decide(event).matched_policy

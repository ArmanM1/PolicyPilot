from copy import deepcopy

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from policypilot.adapters import normalize_shell
from policypilot.approvals import ApprovalError
from policypilot.models import ShellFixtureRequest
from policypilot.policy import PolicyEngine


@pytest.mark.property
@given(st.permutations(tuple(range(14))))
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_policy_order_is_deterministic(engine, permutation):
    rule_data = [
        {"id": rule.id, "priority": rule.priority, "outcome": rule.outcome.value, "reason": rule.reason, "match": deepcopy(rule.match)}
        for rule in engine.rules
    ]
    raw = {
        "version": engine.version,
        "allowlisted_mcp_servers": sorted(engine.allowlisted_mcp_servers),
        "rules": [rule_data[index] for index in permutation],
    }
    rebuilt = PolicyEngine.compile(raw)
    event = normalize_shell(
        ShellFixtureRequest(
            event_id="property-policy-event",
            correlation_id="property-policy-correlation",
            command="git push origin main --force",
            repository_label="protected",
        )
    )
    assert rebuilt.decide(event).model_dump(exclude={"decided_at"}) == engine.decide(event).model_dump(exclude={"decided_at"})


@pytest.mark.property
@given(st.text(min_size=16, max_size=80))
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_random_token_never_consumes_approval(service, token):
    event_id = f"random-token-{abs(hash(token))}"
    envelope = service.process_shell(
        ShellFixtureRequest(event_id=event_id, correlation_id=f"correlation-{event_id}", command="npm install fixture")
    )
    service.approvals.grant(envelope.event.event_id)
    with pytest.raises(ApprovalError):
        service.approvals.consume(envelope.event.event_id, token)


@pytest.mark.property
@given(st.text(min_size=1, max_size=300))
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_arbitrary_shell_text_always_gets_a_classification(engine, value):
    event = normalize_shell(
        ShellFixtureRequest(event_id="fuzz-classify-event", correlation_id="fuzz-classify-correlation", command=value)
    )
    decision = engine.decide(event)
    assert decision.outcome.value in {"allow", "warn", "block", "require_approval"}

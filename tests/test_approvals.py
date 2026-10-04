from datetime import timedelta

import pytest

from policypilot.approvals import ApprovalError
from policypilot.models import ShellFixtureRequest, utc_now


def make_request(event_id: str, command: str = "npm install fixture-package") -> ShellFixtureRequest:
    return ShellFixtureRequest(
        event_id=event_id,
        correlation_id=f"correlation-{event_id}",
        command=command,
    )


def test_approval_is_scoped_and_single_use(service):
    envelope = service.process_shell(make_request("approval-event-01"))
    grant = service.approvals.grant(envelope.event.event_id)
    result = service.approvals.consume(envelope.event.event_id, grant.token)
    assert result.state == "consumed"
    assert result.executed is False
    with pytest.raises(ApprovalError, match="already been consumed"):
        service.approvals.consume(envelope.event.event_id, grant.token)


def test_wrong_event_cannot_use_token(service):
    first = service.process_shell(make_request("approval-event-02"))
    second = service.process_shell(make_request("approval-event-03", "git push origin feature"))
    grant = service.approvals.grant(first.event.event_id)
    with pytest.raises(ApprovalError):
        service.approvals.consume(second.event.event_id, grant.token)


def test_wrong_token_is_rejected(service):
    envelope = service.process_shell(make_request("approval-event-04"))
    service.approvals.grant(envelope.event.event_id)
    with pytest.raises(ApprovalError, match="invalid"):
        service.approvals.consume(envelope.event.event_id, "wrong-token-value-that-is-long")


def test_expired_token_is_rejected(service):
    envelope = service.process_shell(make_request("approval-event-05"))
    now = utc_now()
    grant = service.approvals.grant(envelope.event.event_id, now=now)
    with pytest.raises(ApprovalError, match="expired"):
        service.approvals.consume(envelope.event.event_id, grant.token, now=now + timedelta(minutes=2))


def test_non_approval_decision_cannot_be_approved(service):
    envelope = service.process_shell(make_request("approval-event-06", "git status"))
    with pytest.raises(ApprovalError, match="does not require"):
        service.approvals.grant(envelope.event.event_id)


def test_approval_token_is_hashed_at_rest(service):
    envelope = service.process_shell(make_request("approval-event-07"))
    grant = service.approvals.grant(envelope.event.event_id)
    row = service.store.connection.execute(
        "SELECT token_hash FROM approvals WHERE event_id = ?", (envelope.event.event_id,)
    ).fetchone()
    assert row["token_hash"] != grant.token
    assert len(row["token_hash"]) == 64

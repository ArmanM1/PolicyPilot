from __future__ import annotations

from .adapters import normalize_mcp, normalize_shell
from .approvals import ApprovalService
from .audit import AuditStore
from .models import DecisionEnvelope, MCPFixtureRequest, Outcome, ShellFixtureRequest
from .policy import PolicyEngine


class PolicyPilotService:
    def __init__(self, engine: PolicyEngine, store: AuditStore, approval_ttl_seconds: int = 300):
        self.engine = engine
        self.store = store
        self.approvals = ApprovalService(store, approval_ttl_seconds)

    def process_shell(self, request: ShellFixtureRequest) -> DecisionEnvelope:
        event = normalize_shell(request)
        return self._decide(event)

    def process_mcp(self, request: MCPFixtureRequest) -> DecisionEnvelope:
        event = normalize_mcp(request, self.engine.allowlisted_mcp_servers)
        return self._decide(event)

    def _decide(self, event) -> DecisionEnvelope:
        decision = self.engine.decide(event)
        decision.audit_id = self.store.persist_decision(event, decision)
        state = "pending" if decision.outcome == Outcome.REQUIRE_APPROVAL else "not_required"
        return DecisionEnvelope(decision=decision, event=event, approval_state=state)

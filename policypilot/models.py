from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_ARGUMENT_BYTES = 16_384


class Outcome(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Autonomy(StrEnum):
    SUGGEST = "suggest"
    SUPERVISED = "supervised"
    AUTONOMOUS = "autonomous"


class RiskCategory(StrEnum):
    BENIGN_READ = "benign_read"
    BOUNDED_WRITE = "bounded_write"
    DESTRUCTIVE_FILESYSTEM = "destructive_filesystem"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_EGRESS = "network_egress"
    SOURCE_CONTROL_MUTATION = "source_control_mutation"
    DATABASE_MUTATION = "database_mutation"
    PACKAGE_INSTALL = "package_install"
    UNTRUSTED_MCP = "untrusted_mcp"
    AMBIGUOUS_INVALID = "ambiguous_invalid"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RequestContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=8, max_length=128)
    timestamp: datetime = Field(default_factory=utc_now)
    agent: str = Field(default="fixture-agent", min_length=1, max_length=128)
    repository_label: str = Field(default="sandbox", min_length=1, max_length=128)
    environment: Environment = Environment.DEVELOPMENT
    requested_autonomy: Autonomy = Autonomy.SUPERVISED
    correlation_id: str = Field(default_factory=lambda: str(uuid4()), min_length=8, max_length=128)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class ShellFixtureRequest(RequestContext):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=MAX_ARGUMENT_BYTES)
    cwd: str = Field(default="fixtures/repository", min_length=1, max_length=512)


class MCPParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    server: str = Field(min_length=1, max_length=256)


class MCPFixtureRequest(RequestContext):
    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = Field(pattern=r"^2\.0$")
    id: str | int
    method: str = Field(pattern=r"^tools/call$")
    params: MCPParams


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime
    agent: str
    tool: str
    action: str
    arguments: dict[str, Any]
    repository_label: str
    environment: Environment
    requested_autonomy: Autonomy
    correlation_id: str
    source: str
    risk_category: RiskCategory
    risk_score: int = Field(ge=0, le=100)
    redacted_fields: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    event_id: str
    outcome: Outcome
    matched_policy: str
    reason: str
    policy_version: str
    risk_category: RiskCategory
    risk_score: int
    decided_at: datetime = Field(default_factory=utc_now)
    audit_id: int | None = None
    execution_mode: str = "simulation_only"


class DecisionEnvelope(BaseModel):
    decision: Decision
    event: CanonicalEvent
    approval_state: str = "not_required"
    simulated: bool = True
    executed: bool = False


class ApprovalGrant(BaseModel):
    event_id: str
    token: str
    expires_at: datetime
    state: str


class ApprovalConsumeRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)


class ApprovalResult(BaseModel):
    event_id: str
    state: str
    consumed_at: datetime | None = None
    simulated: bool = True
    executed: bool = False


class PolicySimulationRequest(BaseModel):
    policy_yaml: str = Field(min_length=1, max_length=100_000)

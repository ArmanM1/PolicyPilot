from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import CanonicalEvent, Decision, Outcome


class PolicyCompileError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyRule:
    id: str
    priority: int
    outcome: Outcome
    reason: str
    match: dict[str, Any]

    def matches(self, event: CanonicalEvent) -> bool:
        comparable = {
            "tool": event.tool,
            "action": event.action,
            "environment": event.environment.value,
            "repository_label": event.repository_label,
            "risk_category": event.risk_category.value,
            "requested_autonomy": event.requested_autonomy.value,
        }
        for key, expected in self.match.items():
            if key == "arguments_regex":
                haystack = json.dumps(event.arguments, sort_keys=True, ensure_ascii=False)
                if not re.search(str(expected), haystack, re.IGNORECASE):
                    return False
            elif key.endswith("_in"):
                actual_key = key[:-3]
                if comparable.get(actual_key) not in expected:
                    return False
            elif comparable.get(key) != expected:
                return False
        return True


class PolicyEngine:
    def __init__(self, version: str, rules: tuple[PolicyRule, ...], allowlisted_mcp_servers: set[str]):
        self.version = version
        self.rules = tuple(sorted(rules, key=lambda rule: (-rule.priority, rule.id)))
        self.allowlisted_mcp_servers = allowlisted_mcp_servers

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyCompileError(f"could not load policy: {exc}") from exc
        return cls.compile(raw)

    @classmethod
    def compile(cls, raw: Any) -> "PolicyEngine":
        if not isinstance(raw, dict) or not isinstance(raw.get("version"), str):
            raise PolicyCompileError("policy requires a string version")
        raw_rules = raw.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise PolicyCompileError("policy requires at least one rule")
        seen_ids: set[str] = set()
        signatures: set[tuple[int, str]] = set()
        rules: list[PolicyRule] = []
        allowed_keys = {
            "tool", "action", "environment", "repository_label", "risk_category",
            "requested_autonomy", "tool_in", "action_in", "environment_in",
            "repository_label_in", "risk_category_in", "requested_autonomy_in", "arguments_regex",
        }
        for index, item in enumerate(raw_rules):
            if not isinstance(item, dict):
                raise PolicyCompileError(f"rule {index} must be an object")
            try:
                rule_id = str(item["id"])
                priority = int(item["priority"])
                outcome = Outcome(item["outcome"])
                reason = str(item["reason"])
                match = item.get("match", {})
            except (KeyError, TypeError, ValueError) as exc:
                raise PolicyCompileError(f"invalid rule at index {index}: {exc}") from exc
            if rule_id in seen_ids:
                raise PolicyCompileError(f"duplicate rule id: {rule_id}")
            if not isinstance(match, dict) or set(match) - allowed_keys:
                raise PolicyCompileError(f"rule {rule_id} has unsupported match keys")
            signature = (priority, json.dumps(match, sort_keys=True))
            if signature in signatures:
                raise PolicyCompileError(f"ambiguous rules share priority and match: {rule_id}")
            if "arguments_regex" in match:
                try:
                    re.compile(str(match["arguments_regex"]))
                except re.error as exc:
                    raise PolicyCompileError(f"rule {rule_id} has invalid regex: {exc}") from exc
            seen_ids.add(rule_id)
            signatures.add(signature)
            rules.append(PolicyRule(rule_id, priority, outcome, reason, match))
        if not any(not rule.match for rule in rules):
            raise PolicyCompileError("policy requires an explicit fallback rule")
        servers = raw.get("allowlisted_mcp_servers", [])
        if not isinstance(servers, list) or not all(isinstance(item, str) for item in servers):
            raise PolicyCompileError("allowlisted_mcp_servers must be a string list")
        return cls(raw["version"], tuple(rules), set(servers))

    def decide(self, event: CanonicalEvent) -> Decision:
        matched = next((rule for rule in self.rules if rule.matches(event)), None)
        if matched is None:  # compile requires fallback, retained as fail-closed defense
            return Decision(
                event_id=event.event_id,
                outcome=Outcome.BLOCK,
                matched_policy="implicit_fail_closed",
                reason="No policy rule classified the request.",
                policy_version=self.version,
                risk_category=event.risk_category,
                risk_score=event.risk_score,
            )
        return Decision(
            event_id=event.event_id,
            outcome=matched.outcome,
            matched_policy=matched.id,
            reason=matched.reason,
            policy_version=self.version,
            risk_category=event.risk_category,
            risk_score=event.risk_score,
        )

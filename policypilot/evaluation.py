from __future__ import annotations

import hashlib
import json
import platform
import statistics
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from .adapters import normalize_mcp, normalize_shell
from .approvals import ApprovalError
from .audit import AuditStore
from .models import MCPFixtureRequest, Outcome, ShellFixtureRequest
from .policy import PolicyEngine
from .redaction import REDACTED, redact
from .service import PolicyPilotService


OUTCOMES = [item.value for item in Outcome]
CRITICAL_CATEGORIES = {"destructive_filesystem", "credential_access"}

SYNTHETIC_SECRETS = [
    {"api_key": "fixture-value"},
    {"password": "fixture-password"},
    {"authorization": "Bearer syntheticlongtoken123456789"},
    {"command": "curl -H 'Authorization: Bearer syntheticlongtoken123456789' example.invalid"},
    {"command": "export API_KEY=synthetic-value-123"},
    {"token": "fixture-token"},
    {"value": "sk-abcdefghijklmnopqrstuvwxyz123456"},
    {"value": "ghp_abcdefghijklmnopqrstuvwxyz123456"},
    {"value": "AKIAIOSFODNN7EXAMPLE"},
    {"value": "https://fixture-user:fixture-pass@example.invalid/path"},
    {"nested": {"client_secret": "fixture-client-secret"}},
    {"items": [{"passwd": "fixture-passwd"}]},
    {"value": "token=synthetic-token-value"},
    {"value": "password:hunter-fixture"},
    {"private_key": "fixture-private-key"},
    {"cookie": "fixture-cookie"},
]


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def load_fixtures(path: str | Path) -> tuple[list[dict[str, Any]], str]:
    raw_bytes = Path(path).read_bytes()
    data = yaml.safe_load(raw_bytes)
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("fixtures"), list):
        raise ValueError("invalid evaluation fixture corpus")
    return data["fixtures"], hashlib.sha256(raw_bytes).hexdigest()


def _normalize_fixture(fixture: dict[str, Any], engine: PolicyEngine, event_id: str | None = None):
    common = {
        "event_id": event_id or f"eval-{fixture['id']}-{uuid4()}",
        "agent": fixture.get("agent", "evaluation-agent"),
        "repository_label": fixture.get("repository_label", "sandbox"),
        "environment": fixture.get("environment", "development"),
        "requested_autonomy": fixture.get("requested_autonomy", "supervised"),
        "correlation_id": f"correlation-{uuid4()}",
    }
    if fixture["adapter"] == "shell":
        request = ShellFixtureRequest(command=fixture["command"], cwd=fixture.get("cwd", "fixtures/repository"), **common)
        return normalize_shell(request)
    request = MCPFixtureRequest(
        jsonrpc="2.0",
        id=fixture["id"],
        method="tools/call",
        params=fixture["params"],
        **common,
    )
    return normalize_mcp(request, engine.allowlisted_mcp_servers)


def run_evaluation(
    *,
    policy_path: str | Path,
    fixture_path: str | Path,
    iterations: int = 500,
) -> dict[str, Any]:
    engine = PolicyEngine.from_file(policy_path)
    fixtures, corpus_hash = load_fixtures(fixture_path)
    matrix = {expected: {predicted: 0 for predicted in OUTCOMES} for expected in OUTCOMES}
    per_category: dict[str, dict[str, Any]] = defaultdict(lambda: {"total": 0, "correct": 0, "predictions": Counter()})
    results: list[dict[str, Any]] = []
    critical_false_negatives = 0
    critical_total = 0
    benign_false_positives = 0
    benign_total = 0

    for fixture in fixtures:
        event = _normalize_fixture(fixture, engine)
        decision = engine.decide(event)
        expected = fixture["expected"]
        predicted = decision.outcome.value
        category = fixture["category"]
        matrix[expected][predicted] += 1
        bucket = per_category[category]
        bucket["total"] += 1
        bucket["correct"] += int(expected == predicted)
        bucket["predictions"][predicted] += 1
        if category in CRITICAL_CATEGORIES:
            critical_total += 1
            critical_false_negatives += int(predicted != "block")
        if category == "benign_read":
            benign_total += 1
            benign_false_positives += int(predicted != "allow")
        results.append(
            {
                "id": fixture["id"],
                "category": category,
                "expected": expected,
                "predicted": predicted,
                "matched_policy": decision.matched_policy,
                "correct": expected == predicted,
            }
        )

    temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp.close()
    store = AuditStore(temp.name)
    service = PolicyPilotService(engine, store)
    latencies_ms: list[float] = []
    accepted_with_trace = 0
    for index in range(max(iterations, len(fixtures))):
        fixture = fixtures[index % len(fixtures)]
        started = time.perf_counter_ns()
        event = _normalize_fixture(fixture, engine, event_id=f"bench-{index}-{uuid4()}")
        decision = engine.decide(event)
        decision.audit_id = store.persist_decision(event, decision)
        latencies_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        accepted_with_trace += int(bool(decision.audit_id and decision.policy_version))
    chain = store.verify_chain()

    approval_attempts = 0
    approval_rejections = 0
    for index in range(10):
        fixture = next(item for item in fixtures if item["expected"] == "require_approval")
        event = _normalize_fixture(fixture, engine, event_id=f"approval-{index}-{uuid4()}")
        decision = engine.decide(event)
        decision.audit_id = store.persist_decision(event, decision)
        grant = service.approvals.grant(event.event_id)
        service.approvals.consume(event.event_id, grant.token)
        approval_attempts += 1
        try:
            service.approvals.consume(event.event_id, grant.token)
        except ApprovalError:
            approval_rejections += 1

    redaction_hits = 0
    for secret in SYNTHETIC_SECRETS:
        clean, fields = redact(secret)
        redaction_hits += int(bool(fields) and REDACTED in json.dumps(clean))

    total = len(results)
    correct = sum(item["correct"] for item in results)
    report = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy_version": engine.version,
        "fixture_corpus_sha256": corpus_hash,
        "fixture_count": total,
        "primary_metric": "decision_accuracy",
        "decision_accuracy": correct / total if total else 0,
        "false_negative_rate_critical": critical_false_negatives / critical_total if critical_total else 0,
        "false_positive_rate_benign": benign_false_positives / benign_total if benign_total else 0,
        "audit_completeness": accepted_with_trace / max(iterations, len(fixtures)),
        "audit_chain_valid": chain["valid"],
        "approval_replay_rejection_rate": approval_rejections / approval_attempts,
        "redaction_recall_synthetic": redaction_hits / len(SYNTHETIC_SECRETS),
        "latency_ms": {
            "samples": len(latencies_ms),
            "p50": round(_percentile(latencies_ms, 0.50), 3),
            "p95": round(_percentile(latencies_ms, 0.95), 3),
            "mean": round(statistics.fmean(latencies_ms), 3),
            "scope": "normalize + redact + classify + decide + SQLite audit append",
        },
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor() or "not reported by runtime",
            "python": platform.python_version(),
        },
        "confusion_matrix": matrix,
        "per_category": {
            category: {
                "total": bucket["total"],
                "correct": bucket["correct"],
                "accuracy": bucket["correct"] / bucket["total"],
                "predictions": dict(bucket["predictions"]),
            }
            for category, bucket in sorted(per_category.items())
        },
        "errors": [item for item in results if not item["correct"]],
        "results": results,
        "limitations": [
            "Fixtures are synthetic and do not estimate real-world attack prevalence.",
            "Risk classification is a bounded prototype signature library, not complete DLP.",
            "Latency is a local single-process measurement and excludes network transport and UI rendering.",
            "The default simulator never executes submitted tool requests.",
        ],
    }
    store.close()
    Path(temp.name).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(temp.name + suffix).unlink(missing_ok=True)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PolicyPilot evaluation report",
        "",
        f"Generated: `{report['generated_at']}`  ",
        f"Policy: `{report['policy_version']}`  ",
        f"Frozen fixture SHA-256: `{report['fixture_corpus_sha256']}`",
        "",
        "## Key metrics",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Decision accuracy | {report['decision_accuracy']:.2%} ({report['fixture_count']} fixtures) |",
        f"| Critical false-negative rate | {report['false_negative_rate_critical']:.2%} |",
        f"| Benign false-positive rate | {report['false_positive_rate_benign']:.2%} |",
        f"| Audit completeness | {report['audit_completeness']:.2%} |",
        f"| Approval replay rejection | {report['approval_replay_rejection_rate']:.2%} |",
        f"| Synthetic redaction recall | {report['redaction_recall_synthetic']:.2%} |",
        f"| Added latency p50 / p95 | {report['latency_ms']['p50']:.3f} ms / {report['latency_ms']['p95']:.3f} ms |",
        "",
        "## Per-category results",
        "",
        "| Category | Correct | Accuracy | Predictions |",
        "|---|---:|---:|---|",
    ]
    for category, bucket in report["per_category"].items():
        lines.append(
            f"| {category} | {bucket['correct']}/{bucket['total']} | {bucket['accuracy']:.2%} | "
            f"`{json.dumps(bucket['predictions'], sort_keys=True)}` |"
        )
    lines.extend(["", "## Confusion matrix", "", "Rows are expected; columns are predicted.", ""])
    lines.append("| Expected \\ Predicted | " + " | ".join(OUTCOMES) + " |")
    lines.append("|---|" + "---:|" * len(OUTCOMES))
    for expected in OUTCOMES:
        lines.append(
            f"| {expected} | " + " | ".join(str(report["confusion_matrix"][expected][item]) for item in OUTCOMES) + " |"
        )
    lines.extend(["", "## Measurement boundary", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend(["", f"Hardware/runtime: `{json.dumps(report['hardware'], sort_keys=True)}`", ""])
    return "\n".join(lines)

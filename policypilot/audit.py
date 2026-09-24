from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import CanonicalEvent, Decision, utc_now


GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class DuplicateEventError(ValueError):
    pass


class AuditStore:
    """SQLite-backed immutable event ledger with a SHA-256 hash chain."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def _initialize(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    action TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    repository_label TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    requested_autonomy TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    risk_category TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    redacted_fields_json TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    matched_policy TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    decided_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_entries (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
                    token_hash TEXT NOT NULL UNIQUE,
                    event_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    granted_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_events_decided_at ON events(decided_at DESC);
                CREATE INDEX IF NOT EXISTS idx_events_outcome ON events(outcome);
                CREATE INDEX IF NOT EXISTS idx_events_agent_repo ON events(agent, repository_label);
                CREATE INDEX IF NOT EXISTS idx_audit_event_id ON audit_entries(event_id, audit_id);
                CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS events_no_delete
                BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_update
                BEFORE UPDATE ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_delete
                BEFORE DELETE ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END;
                """
            )
            self._connection.execute("PRAGMA optimize")

    def close(self) -> None:
        self._connection.close()

    def append_audit(self, event_id: str, event_type: str, payload: dict[str, Any]) -> int:
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT entry_hash FROM audit_entries ORDER BY audit_id DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["entry_hash"] if row else GENESIS_HASH
            recorded_at = utc_now().isoformat()
            payload_json = canonical_json(payload)
            material = f"{previous_hash}|{event_id}|{event_type}|{recorded_at}|{payload_json}"
            entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
            cursor = self._connection.execute(
                """INSERT INTO audit_entries
                (event_id, event_type, recorded_at, payload_json, previous_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (event_id, event_type, recorded_at, payload_json, previous_hash, entry_hash),
            )
            return int(cursor.lastrowid)

    def persist_decision(self, event: CanonicalEvent, decision: Decision) -> int:
        values = (
            event.event_id,
            event.timestamp.isoformat(),
            event.agent,
            event.tool,
            event.action,
            canonical_json(event.arguments),
            event.repository_label,
            event.environment.value,
            event.requested_autonomy.value,
            event.correlation_id,
            event.source,
            event.risk_category.value,
            event.risk_score,
            canonical_json(event.redacted_fields),
            decision.outcome.value,
            decision.matched_policy,
            decision.reason,
            decision.policy_version,
            decision.decided_at.isoformat(),
        )
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """INSERT INTO events (
                    event_id, timestamp, agent, tool, action, arguments_json,
                    repository_label, environment, requested_autonomy, correlation_id,
                    source, risk_category, risk_score, redacted_fields_json, outcome,
                    matched_policy, reason, policy_version, decided_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    values,
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEventError(f"event id already exists: {event.event_id}") from exc
        return self.append_audit(
            event.event_id,
            "decision.recorded",
            {
                "event": event.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json", exclude={"audit_id"}),
            },
        )

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = self._connection.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return self._decode_event(row) if row else None

    def list_events(
        self,
        *,
        limit: int = 100,
        outcome: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        if query:
            clauses.append("(event_id LIKE ? OR agent LIKE ? OR action LIKE ? OR repository_label LIKE ?)")
            like = f"%{query}%"
            params.extend([like, like, like, like])
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 500)))
        rows = self._connection.execute(
            f"SELECT * FROM events{where} ORDER BY decided_at DESC LIMIT ?", params
        ).fetchall()
        return [self._decode_event(row) for row in rows]

    def _decode_event(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["arguments"] = json.loads(result.pop("arguments_json"))
        result["redacted_fields"] = json.loads(result.pop("redacted_fields_json"))
        approval = self._connection.execute(
            "SELECT state, expires_at, consumed_at FROM approvals WHERE event_id = ?", (result["event_id"],)
        ).fetchone()
        result["approval_state"] = approval["state"] if approval else (
            "pending" if result["outcome"] == "require_approval" else "not_required"
        )
        return result

    def summary(self) -> dict[str, Any]:
        total = self._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_outcome = {
            row["outcome"]: row["count"]
            for row in self._connection.execute(
                "SELECT outcome, COUNT(*) AS count FROM events GROUP BY outcome"
            ).fetchall()
        }
        avg_risk = self._connection.execute("SELECT COALESCE(AVG(risk_score), 0) FROM events").fetchone()[0]
        agents = [
            dict(row)
            for row in self._connection.execute(
                """SELECT agent, COUNT(*) AS events, ROUND(AVG(risk_score), 1) AS avg_risk
                FROM events GROUP BY agent ORDER BY avg_risk DESC, events DESC LIMIT 8"""
            ).fetchall()
        ]
        repositories = [
            dict(row)
            for row in self._connection.execute(
                """SELECT repository_label, COUNT(*) AS events, ROUND(AVG(risk_score), 1) AS avg_risk
                FROM events GROUP BY repository_label ORDER BY avg_risk DESC, events DESC LIMIT 8"""
            ).fetchall()
        ]
        return {
            "total_events": total,
            "by_outcome": {key: by_outcome.get(key, 0) for key in ("allow", "warn", "block", "require_approval")},
            "average_risk": round(float(avg_risk), 1),
            "agents": agents,
            "repositories": repositories,
            "audit_chain_valid": self.verify_chain()["valid"],
        }

    def verify_chain(self) -> dict[str, Any]:
        previous = GENESIS_HASH
        count = 0
        for row in self._connection.execute("SELECT * FROM audit_entries ORDER BY audit_id").fetchall():
            material = (
                f"{previous}|{row['event_id']}|{row['event_type']}|"
                f"{row['recorded_at']}|{row['payload_json']}"
            )
            expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous or row["entry_hash"] != expected:
                return {"valid": False, "entries": count, "failed_audit_id": row["audit_id"]}
            previous = row["entry_hash"]
            count += 1
        return {"valid": True, "entries": count, "head_hash": previous}

    def export_jsonl(self) -> str:
        rows = self._connection.execute("SELECT * FROM audit_entries ORDER BY audit_id").fetchall()
        return "\n".join(canonical_json(dict(row)) for row in rows) + ("\n" if rows else "")

    @property
    def connection(self) -> sqlite3.Connection:
        return self._connection

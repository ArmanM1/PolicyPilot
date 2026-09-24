from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from .audit import AuditStore, canonical_json
from .models import ApprovalGrant, ApprovalResult, utc_now


class ApprovalError(ValueError):
    pass


class ApprovalService:
    def __init__(self, store: AuditStore, ttl_seconds: int = 300):
        self.store = store
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _event_digest(event: dict) -> str:
        stable = {
            key: value
            for key, value in event.items()
            if key not in {"approval_state", "decided_at"}
        }
        return hashlib.sha256(canonical_json(stable).encode("utf-8")).hexdigest()

    def grant(self, event_id: str, now: datetime | None = None) -> ApprovalGrant:
        now = (now or utc_now()).astimezone(timezone.utc)
        event = self.store.get_event(event_id)
        if event is None:
            raise ApprovalError("event not found")
        if event["outcome"] != "require_approval":
            raise ApprovalError("event does not require approval")
        existing = self.store.connection.execute(
            "SELECT state FROM approvals WHERE event_id = ?", (event_id,)
        ).fetchone()
        if existing:
            raise ApprovalError(f"approval already exists in state {existing['state']}")
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=self.ttl_seconds)
        with self.store.connection:
            self.store.connection.execute(
                """INSERT INTO approvals
                (event_id, token_hash, event_digest, state, granted_at, expires_at, consumed_at)
                VALUES (?, ?, ?, 'granted', ?, ?, NULL)""",
                (
                    event_id,
                    self._hash_token(token),
                    self._event_digest(event),
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
        self.store.append_audit(
            event_id,
            "approval.granted",
            {"event_id": event_id, "state": "granted", "expires_at": expires_at.isoformat()},
        )
        return ApprovalGrant(event_id=event_id, token=token, expires_at=expires_at, state="granted")

    def consume(self, event_id: str, token: str, now: datetime | None = None) -> ApprovalResult:
        now = (now or utc_now()).astimezone(timezone.utc)
        token_hash = self._hash_token(token)
        row = self.store.connection.execute(
            "SELECT * FROM approvals WHERE event_id = ?", (event_id,)
        ).fetchone()
        event = self.store.get_event(event_id)
        error: str | None = None
        if row is None or event is None:
            error = "approval not found"
        elif not hmac.compare_digest(row["token_hash"], token_hash):
            error = "approval token is invalid"
        elif row["state"] != "granted":
            error = "approval token has already been consumed"
        elif now >= datetime.fromisoformat(row["expires_at"]):
            error = "approval token has expired"
        elif not hmac.compare_digest(row["event_digest"], self._event_digest(event)):
            error = "event no longer matches approval scope"
        if error:
            self.store.append_audit(event_id, "approval.rejected", {"event_id": event_id, "reason": error})
            raise ApprovalError(error)
        try:
            with self.store.connection:
                cursor = self.store.connection.execute(
                    """UPDATE approvals SET state = 'consumed', consumed_at = ?
                    WHERE event_id = ? AND state = 'granted'""",
                    (now.isoformat(), event_id),
                )
                if cursor.rowcount != 1:
                    raise ApprovalError("approval token has already been consumed")
        except sqlite3.DatabaseError as exc:
            raise ApprovalError(f"approval state transition failed: {exc}") from exc
        self.store.append_audit(
            event_id,
            "approval.consumed",
            {"event_id": event_id, "state": "consumed", "consumed_at": now.isoformat(), "executed": False},
        )
        return ApprovalResult(event_id=event_id, state="consumed", consumed_at=now)

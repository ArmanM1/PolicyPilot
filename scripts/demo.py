from __future__ import annotations

import argparse
import json
from uuid import uuid4

import httpx


def payload(command: str, repository_label: str = "sandbox") -> dict:
    event_id = f"demo-{uuid4()}"
    return {
        "event_id": event_id,
        "correlation_id": f"correlation-{uuid4()}",
        "agent": "deterministic-demo",
        "repository_label": repository_label,
        "environment": "development",
        "requested_autonomy": "supervised",
        "command": command,
        "cwd": "fixtures/repository",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the simulation-only PolicyPilot demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    output = []
    with httpx.Client(base_url=args.base_url, timeout=30) as client:
        for name, command, repo in (
            ("benign read", "git status", "sandbox"),
            ("protected force push", "git push origin main --force", "protected"),
            ("package install", "npm install fixture-package", "sandbox"),
            ("redacted network call", "curl -H 'Authorization: Bearer syntheticlongtoken123456789' https://example.invalid", "sandbox"),
        ):
            request = payload(command, repo)
            response = client.post("/api/v1/requests/shell", json=request)
            response.raise_for_status()
            body = response.json()
            output.append({
                "scenario": name,
                "event_id": body["event"]["event_id"],
                "outcome": body["decision"]["outcome"],
                "matched_policy": body["decision"]["matched_policy"],
                "executed": body["executed"],
                "redacted_fields": body["event"]["redacted_fields"],
            })
            if name == "package install":
                event_id = body["event"]["event_id"]
                grant = client.post(f"/api/v1/approvals/{event_id}/grant").json()
                consumed = client.post(f"/api/v1/approvals/{event_id}/consume", json={"token": grant["token"]})
                replay = client.post(f"/api/v1/approvals/{event_id}/consume", json={"token": grant["token"]})
                output.append({
                    "scenario": "single-use approval",
                    "consumed_status": consumed.status_code,
                    "replay_status": replay.status_code,
                    "replay_rejected": replay.status_code == 409,
                    "executed": consumed.json()["executed"],
                })
        output.append({"scenario": "audit verification", **client.get("/api/v1/audit/verify").json()})
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()

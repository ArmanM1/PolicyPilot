# PolicyPilot

PolicyPilot is a local, fixture-driven firewall for AI-agent tool use. It intercepts structured shell and MCP-style requests, redacts secret-shaped values, applies deterministic versioned policy, models scoped human approval, and writes an immutable hash-chained audit trail.

**The default product never executes submitted commands.** Every gateway response includes `simulated: true` and `executed: false`. The optional toy sandbox adapter is disabled and disconnected from the HTTP path.

## What is built

- FastAPI gateway for structured shell and MCP JSON-RPC fixture requests.
- Canonical event schema with event/correlation IDs, timestamps, agent/tool/action, repository and environment labels, autonomy, risk, and redacted arguments.
- Declarative YAML rules with priority, deterministic ID tie-breaking, policy versioning, explanations, and fail-closed fallback.
- Outcomes: `allow`, `warn`, `block`, and `require_approval`.
- Random approval tokens hashed at rest, scoped to one immutable event, expiring, atomically single-use, and replay-audited.
- SQLite event store with update/delete prevention, searchable indexes, append-only audit entries, and a SHA-256 hash chain.
- React/Vinext dashboard with live decisions, filters, redacted details, approval/replay demo, posture summaries, and evaluation results.
- Frozen 49-fixture corpus, confusion matrix, per-category results, synthetic redaction checks, audit completeness, replay rejection, and local p50/p95 latency.
- Unit, golden, integration, property, fuzz, failure-mode, security, API, and rendered-UI tests.
- Container setup, deterministic demo, threat model, limitations, and architecture notes.

## Run locally

Python 3.11+ and Node 22.13+ are required.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
npm ci
```

Start the API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn policypilot.api:app --host 127.0.0.1 --port 8000
```

Start the dashboard in a second terminal:

```powershell
npm run dev
```

Open the URL printed by the dashboard. The API explorer is at `http://127.0.0.1:8000/docs`.

Or run the clean two-container setup:

```powershell
docker compose up --build -d
```

The containerized dashboard is at `http://127.0.0.1:3001`; the API remains at `http://127.0.0.1:8000`. Stop both with `docker compose down`.

## Deterministic demo

With the API running:

```powershell
.\.venv\Scripts\python.exe scripts\demo.py
```

The script submits a benign read, protected force push, package installation, and secret-bearing network fixture. It consumes a one-event approval, proves the replay is rejected, and verifies the audit chain. Nothing is executed.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest --cov=policypilot --cov-report=term-missing
npm test
.\.venv\Scripts\python.exe -m policypilot.cli evaluate --iterations 500
```

The evaluation command writes `reports/evaluation.json` and `reports/EVALUATION.md`. The report includes the fixture SHA-256 so results remain tied to the frozen labels.

## Example requests

Shell fixture:

```json
{
  "event_id": "example-shell-0001",
  "correlation_id": "example-correlation-0001",
  "agent": "fixture-agent",
  "repository_label": "protected",
  "environment": "development",
  "requested_autonomy": "supervised",
  "command": "git push origin main --force",
  "cwd": "fixtures/repository"
}
```

POST it to `/api/v1/requests/shell`. It is classified and blocked without execution.

MCP-style fixture:

```json
{
  "event_id": "example-mcp-0001",
  "correlation_id": "example-correlation-0002",
  "agent": "fixture-agent",
  "repository_label": "sandbox",
  "environment": "development",
  "requested_autonomy": "supervised",
  "jsonrpc": "2.0",
  "id": "rpc-1",
  "method": "tools/call",
  "params": {
    "name": "list_files",
    "arguments": {"path": "fixtures/repository"},
    "server": "policypilot.toy-files"
  }
}
```

POST it to `/api/v1/requests/mcp`.

## Project map

- `policypilot/` — schemas, adapters, redaction, risk, policy, approval, audit, API, simulator, and evaluation code.
- `policies/default.yaml` — versioned default policy.
- `fixtures/evaluation.yaml` — frozen labeled corpus.
- `app/` — dashboard.
- `tests/` — Python and rendered-UI verification.
- `docs/THREAT_MODEL.md` — assets, actors, boundaries, abuse cases, and mitigations.
- `docs/LIMITATIONS.md` — explicit evidence and production-readiness limits.
- `reports/` — generated artifact-backed measurements.

## Security boundary

This prototype does not claim complete command parsing, DLP, MCP identity, production isolation, multi-tenant authorization, or protection from a privileged local administrator. See the [threat model](docs/THREAT_MODEL.md) and [limitations](docs/LIMITATIONS.md) before describing or extending it.

from __future__ import annotations

import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError
import yaml

from .approvals import ApprovalError
from .audit import AuditStore, DuplicateEventError
from .evaluation import _normalize_fixture, load_fixtures, run_evaluation
from .models import ApprovalConsumeRequest, MCPFixtureRequest, PolicySimulationRequest, ShellFixtureRequest
from .policy import PolicyCompileError, PolicyEngine
from .service import PolicyPilotService


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "policies" / "default.yaml"
DEFAULT_DB = ROOT / "data" / "policypilot.db"


def build_service(policy_path: str | Path | None = None, db_path: str | Path | None = None) -> PolicyPilotService:
    engine = PolicyEngine.from_file(policy_path or os.getenv("POLICYPILOT_POLICY", DEFAULT_POLICY))
    store = AuditStore(db_path or os.getenv("POLICYPILOT_DB", DEFAULT_DB))
    return PolicyPilotService(engine, store)


def create_app(service: PolicyPilotService | None = None) -> FastAPI:
    owned_service = service

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.service = owned_service or build_service()
        yield
        if owned_service is None:
            app.state.service.store.close()

    app = FastAPI(
        title="PolicyPilot API",
        version="0.1.0",
        description="Simulation-only policy enforcement for structured AI-agent tool requests.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    def get_service(request: Request) -> PolicyPilotService:
        return request.app.state.service

    @app.exception_handler(DuplicateEventError)
    async def duplicate_handler(_request: Request, exc: DuplicateEventError):
        return JSONResponse(status_code=409, content={"detail": str(exc), "fail_closed": True})

    @app.exception_handler(PolicyCompileError)
    @app.exception_handler(sqlite3.DatabaseError)
    async def storage_handler(_request: Request, exc: Exception):
        return JSONResponse(status_code=503, content={"detail": str(exc), "fail_closed": True})

    @app.get("/api/v1/health")
    def health(request: Request):
        service = get_service(request)
        chain = service.store.verify_chain()
        return {
            "status": "ok" if chain["valid"] else "degraded",
            "execution_mode": "simulation_only",
            "sandbox_enabled": False,
            "policy_version": service.engine.version,
            "audit_chain": chain,
        }

    @app.post("/api/v1/requests/shell", status_code=201)
    def submit_shell(payload: ShellFixtureRequest, request: Request):
        return get_service(request).process_shell(payload)

    @app.post("/api/v1/requests/mcp", status_code=201)
    def submit_mcp(payload: MCPFixtureRequest, request: Request):
        try:
            return get_service(request).process_mcp(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"message": str(exc), "fail_closed": True}) from exc

    @app.get("/api/v1/events")
    def events(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        outcome: str | None = None,
        q: str | None = None,
    ):
        return {"items": get_service(request).store.list_events(limit=limit, outcome=outcome, query=q)}

    @app.get("/api/v1/events/{event_id}")
    def event(event_id: str, request: Request):
        result = get_service(request).store.get_event(event_id)
        if result is None:
            raise HTTPException(status_code=404, detail="event not found")
        return result

    @app.get("/api/v1/metrics")
    def metrics(request: Request):
        return get_service(request).store.summary()

    @app.get("/api/v1/policy")
    def policy(request: Request):
        service = get_service(request)
        return {
            "version": service.engine.version,
            "allowlisted_mcp_servers": sorted(service.engine.allowlisted_mcp_servers),
            "rules": [
                {
                    "id": rule.id,
                    "priority": rule.priority,
                    "outcome": rule.outcome,
                    "reason": rule.reason,
                    "match": rule.match,
                }
                for rule in service.engine.rules
            ],
        }

    @app.post("/api/v1/policy/simulate")
    def simulate_policy(payload: PolicySimulationRequest, request: Request):
        try:
            proposed = PolicyEngine.compile(yaml.safe_load(payload.policy_yaml))
            fixtures, corpus_hash = load_fixtures(ROOT / "fixtures" / "evaluation.yaml")
            current = get_service(request).engine
            changes = []
            for fixture in fixtures:
                current_event = _normalize_fixture(fixture, current)
                proposed_event = _normalize_fixture(fixture, proposed)
                before = current.decide(current_event).outcome.value
                after = proposed.decide(proposed_event).outcome.value
                if before != after:
                    changes.append({"id": fixture["id"], "category": fixture["category"], "before": before, "after": after})
            return {
                "current_version": current.version,
                "proposed_version": proposed.version,
                "fixture_corpus_sha256": corpus_hash,
                "fixtures_compared": len(fixtures),
                "changed_decisions": changes,
                "executed": False,
            }
        except (yaml.YAMLError, PolicyCompileError, ValueError) as exc:
            raise HTTPException(status_code=422, detail={"message": str(exc), "fail_closed": True}) from exc

    @app.post("/api/v1/approvals/{event_id}/grant", status_code=201)
    def grant(event_id: str, request: Request):
        try:
            return get_service(request).approvals.grant(event_id)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/approvals/{event_id}/consume")
    def consume(event_id: str, payload: ApprovalConsumeRequest, request: Request):
        try:
            return get_service(request).approvals.consume(event_id, payload.token)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/audit/verify")
    def verify(request: Request):
        return get_service(request).store.verify_chain()

    @app.get("/api/v1/audit/export", response_class=PlainTextResponse)
    def export(request: Request):
        return get_service(request).store.export_jsonl()

    @app.post("/api/v1/evaluation/run")
    def evaluation():
        try:
            return run_evaluation(policy_path=DEFAULT_POLICY, fixture_path=ROOT / "fixtures" / "evaluation.yaml", iterations=250)
        except (OSError, ValidationError, ValueError) as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


app = create_app()

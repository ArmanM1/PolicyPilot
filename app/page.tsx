"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_POLICY_API ?? "http://localhost:8000";

type Outcome = "allow" | "warn" | "block" | "require_approval";

type EventRecord = {
  event_id: string;
  timestamp: string;
  agent: string;
  tool: string;
  action: string;
  arguments: Record<string, unknown>;
  repository_label: string;
  environment: string;
  correlation_id: string;
  risk_category: string;
  risk_score: number;
  redacted_fields: string[];
  outcome: Outcome;
  matched_policy: string;
  reason: string;
  policy_version: string;
  decided_at: string;
  approval_state: string;
};

type Metrics = {
  total_events: number;
  by_outcome: Record<Outcome, number>;
  average_risk: number;
  audit_chain_valid: boolean;
  agents: Array<{ agent: string; events: number; avg_risk: number }>;
  repositories: Array<{ repository_label: string; events: number; avg_risk: number }>;
};

type Evaluation = {
  fixture_count: number;
  decision_accuracy: number;
  false_negative_rate_critical: number;
  false_positive_rate_benign: number;
  audit_completeness: number;
  approval_replay_rejection_rate: number;
  redaction_recall_synthetic: number;
  latency_ms: { p50: number; p95: number; samples: number };
};

const emptyMetrics: Metrics = {
  total_events: 0,
  by_outcome: { allow: 0, warn: 0, block: 0, require_approval: 0 },
  average_risk: 0,
  audit_chain_valid: true,
  agents: [],
  repositories: [],
};

const demos = [
  { id: "read", label: "Read repo", command: "git status", repo: "sandbox", tone: "allow" },
  { id: "force", label: "Force push", command: "git push origin main --force", repo: "protected", tone: "block" },
  { id: "package", label: "Install package", command: "npm install fixture-package", repo: "sandbox", tone: "approval" },
  {
    id: "secret",
    label: "Secret-bearing call",
    command: "curl -H 'Authorization: Bearer syntheticlongtoken123456789' https://example.invalid",
    repo: "sandbox",
    tone: "warn",
  },
] as const;

function compactId(value: string) {
  return value.length > 19 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function label(value: string) {
  return value.replaceAll("_", " ");
}

function relativeTime(value: string) {
  const delta = Math.max(0, Date.now() - new Date(value).getTime());
  if (delta < 60_000) return `${Math.floor(delta / 1000)}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function Home() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [metrics, setMetrics] = useState<Metrics>(emptyMetrics);
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const [filter, setFilter] = useState<"all" | Outcome>("all");
  const [query, setQuery] = useState("");
  const [online, setOnline] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState("Ready for fixture traffic");
  const [tokens, setTokens] = useState<Record<string, string>>({});
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null);

  const refresh = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "100" });
      if (filter !== "all") params.set("outcome", filter);
      if (query.trim()) params.set("q", query.trim());
      const [eventResponse, metricResponse] = await Promise.all([
        fetch(`${API}/api/v1/events?${params}`, { cache: "no-store" }),
        fetch(`${API}/api/v1/metrics`, { cache: "no-store" }),
      ]);
      if (!eventResponse.ok || !metricResponse.ok) throw new Error("gateway unavailable");
      const eventData = (await eventResponse.json()) as { items: EventRecord[] };
      setEvents(eventData.items);
      setMetrics((await metricResponse.json()) as Metrics);
      setSelected((current) => {
        if (!current) return eventData.items[0] ?? null;
        return eventData.items.find((item) => item.event_id === current.event_id) ?? eventData.items[0] ?? null;
      });
      setOnline(true);
    } catch {
      setOnline(false);
      setNotice("API offline — start the local service to stream decisions");
    }
  }, [filter, query]);

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const timer = window.setInterval(() => void refresh(), 8_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [refresh]);

  async function submitDemo(demo: (typeof demos)[number]) {
    setBusy(demo.id);
    setNotice(`Intercepting ${demo.label.toLowerCase()} fixture…`);
    try {
      const eventId = `demo-${crypto.randomUUID()}`;
      const response = await fetch(`${API}/api/v1/requests/shell`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_id: eventId,
          correlation_id: `correlation-${crypto.randomUUID()}`,
          agent: "dashboard-demo",
          repository_label: demo.repo,
          environment: "development",
          requested_autonomy: "supervised",
          command: demo.command,
          cwd: "fixtures/repository",
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail ?? "request rejected");
      setNotice(`${demo.label}: ${label(body.decision.outcome)} · nothing executed`);
      await refresh();
      const current = await fetch(`${API}/api/v1/events/${eventId}`).then((value) => value.json());
      setSelected(current as EventRecord);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not submit fixture");
    } finally {
      setBusy(null);
    }
  }

  async function approveOnce(event: EventRecord) {
    setBusy(`approve-${event.event_id}`);
    try {
      const grantResponse = await fetch(`${API}/api/v1/approvals/${event.event_id}/grant`, { method: "POST" });
      const grant = await grantResponse.json();
      if (!grantResponse.ok) throw new Error(grant.detail ?? "Approval could not be granted");
      setTokens((current) => ({ ...current, [event.event_id]: grant.token }));
      const consumeResponse = await fetch(`${API}/api/v1/approvals/${event.event_id}/consume`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: grant.token }),
      });
      if (!consumeResponse.ok) throw new Error("Approval could not be consumed");
      setNotice("Single-use approval consumed · simulator recorded zero execution");
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Approval failed closed");
    } finally {
      setBusy(null);
    }
  }

  async function replayApproval(event: EventRecord) {
    const token = tokens[event.event_id];
    if (!token) return;
    setBusy(`replay-${event.event_id}`);
    const response = await fetch(`${API}/api/v1/approvals/${event.event_id}/consume`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    setNotice(response.status === 409 ? "Replay rejected as designed" : "Unexpected replay response — inspect audit");
    setBusy(null);
    await refresh();
  }

  async function runEvaluation() {
    setBusy("evaluation");
    setNotice("Running the frozen policy evaluation…");
    try {
      const response = await fetch(`${API}/api/v1/evaluation/run`, { method: "POST" });
      if (!response.ok) throw new Error("Evaluation could not complete");
      const result = (await response.json()) as Evaluation;
      setEvaluation(result);
      setNotice(`${result.fixture_count} fixtures measured · ${(result.decision_accuracy * 100).toFixed(1)}% exact accuracy`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Evaluation failed");
    } finally {
      setBusy(null);
    }
  }

  const decisionTotal = useMemo(
    () => Object.values(metrics.by_outcome).reduce((sum, value) => sum + value, 0),
    [metrics.by_outcome],
  );

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><span>PP</span></div>
          <div><strong>PolicyPilot</strong><span>AGENT TOOL FIREWALL</span></div>
        </div>
        <div className="topbar-center">
          <span className={`pulse-dot ${online ? "online" : "offline"}`} aria-hidden="true" />
          <span>{online ? "Gateway online" : "Gateway offline"}</span>
          <span className="divider" />
          <span>Policy 2026.08.1</span>
        </div>
        <div className="safety-pill"><span className="shield-glyph">◇</span> SIMULATION ONLY</div>
      </header>

      <div className="workspace">
        <aside className="sidebar">
          <nav aria-label="Primary navigation">
            <span className="nav-label">CONTROL</span>
            <button className="nav-item active"><span className="nav-icon">⌁</span>Live decisions<span className="nav-count">{metrics.total_events}</span></button>
            <a className="nav-item" href={`${API}/docs`} target="_blank" rel="noreferrer"><span className="nav-icon">{`{}`}</span>API explorer</a>
            <a className="nav-item" href={`${API}/api/v1/audit/export`} target="_blank" rel="noreferrer"><span className="nav-icon">⇩</span>Audit export</a>
            <span className="nav-label second">POSTURE</span>
            <button className="nav-item"><span className="nav-icon">⌘</span>Policy rules<span className="nav-count">14</span></button>
            <button className="nav-item" onClick={() => void runEvaluation()}><span className="nav-icon">◫</span>Evaluation</button>
          </nav>
          <div className="sidebar-foot">
            <div className="chain-status"><span>◆</span><div><b>Audit chain</b><small>{metrics.audit_chain_valid ? "Verified & intact" : "Verification failed"}</small></div></div>
            <div className="scope-note">Local fixture traffic only<br />No commands are executed</div>
          </div>
        </aside>

        <section className="main-canvas">
          <div className="eyebrow"><span>CONTROL PLANE</span><span>/</span><span>LIVE TRAFFIC</span></div>
          <div className="hero-row">
            <div>
              <h1>Every tool call.<br /><em>Under control.</em></h1>
              <p>Intercept, classify, and explain agent actions before they cross the execution boundary.</p>
            </div>
            <div className="hero-aside">
              <span>SAFETY BOUNDARY</span>
              <b>0</b>
              <small>commands executed</small>
            </div>
          </div>

          <div className="metric-grid" aria-label="Decision metrics">
            <article className="metric-card accent-lime"><span>DECISIONS</span><strong>{metrics.total_events}</strong><small>accepted requests</small></article>
            <article className="metric-card accent-red"><span>BLOCKED</span><strong>{metrics.by_outcome.block}</strong><small>{decisionTotal ? ((metrics.by_outcome.block / decisionTotal) * 100).toFixed(0) : 0}% of traffic</small></article>
            <article className="metric-card accent-amber"><span>NEEDS APPROVAL</span><strong>{metrics.by_outcome.require_approval}</strong><small>scoped & expiring</small></article>
            <article className="metric-card accent-cyan"><span>MEAN RISK</span><strong>{metrics.average_risk}</strong><small>out of 100</small></article>
          </div>

          <section className="demo-strip" aria-labelledby="demo-title">
            <div className="demo-copy"><span className="section-index">01</span><div><h2 id="demo-title">Intercept a fixture</h2><p>Requests are decided, redacted, and audited — never run.</p></div></div>
            <div className="demo-actions">
              {demos.map((demo) => (
                <button key={demo.id} className={`demo-button ${demo.tone}`} disabled={!online || busy !== null} onClick={() => void submitDemo(demo)}>
                  <span>{busy === demo.id ? "…" : demo.tone === "allow" ? "↗" : demo.tone === "block" ? "×" : demo.tone === "approval" ? "!" : "⌁"}</span>{demo.label}
                </button>
              ))}
            </div>
          </section>

          <div className="content-grid">
            <section className="traffic-panel">
              <div className="panel-head">
                <div><span className="section-index">02</span><h2>Decision stream</h2></div>
                <div className="stream-live"><span /> LIVE</div>
              </div>
              <div className="filters">
                <label className="search-box"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search events, agents, actions" aria-label="Search events" /></label>
                <div className="filter-tabs">
                  {(["all", "allow", "warn", "block", "require_approval"] as const).map((item) => (
                    <button key={item} className={filter === item ? "active" : ""} onClick={() => setFilter(item)}>{item === "require_approval" ? "approval" : item}</button>
                  ))}
                </div>
              </div>
              <div className="event-table" role="table" aria-label="Policy decisions">
                <div className="table-row table-header" role="row"><span>DECISION</span><span>REQUEST</span><span>RISK</span><span>WHEN</span></div>
                {events.length ? events.map((event) => (
                  <button key={event.event_id} className={`table-row event-row ${selected?.event_id === event.event_id ? "selected" : ""}`} onClick={() => setSelected(event)} role="row">
                    <span><i className={`decision-dot ${event.outcome}`} />{event.outcome === "require_approval" ? "approval" : event.outcome}</span>
                    <span className="request-cell"><b>{event.action}</b><small>{event.agent} · {compactId(event.event_id)}</small></span>
                    <span><span className={`risk-score risk-${event.risk_score >= 80 ? "high" : event.risk_score >= 40 ? "medium" : "low"}`}>{event.risk_score}</span></span>
                    <span>{relativeTime(event.decided_at)}</span>
                  </button>
                )) : (
                  <div className="empty-state"><span>⌁</span><b>No fixture traffic yet</b><p>Use an intercept button above to create the first traceable decision.</p></div>
                )}
              </div>
            </section>

            <aside className="detail-panel" aria-label="Selected decision details">
              <div className="panel-head"><div><span className="section-index">03</span><h2>Decision trace</h2></div></div>
              {selected ? (
                <div className="detail-content">
                  <div className={`verdict verdict-${selected.outcome}`}><span>POLICY VERDICT</span><strong>{selected.outcome === "require_approval" ? "REQUIRE APPROVAL" : selected.outcome.toUpperCase()}</strong><small>{selected.reason}</small></div>
                  <dl className="trace-grid">
                    <div><dt>EVENT</dt><dd title={selected.event_id}>{compactId(selected.event_id)}</dd></div>
                    <div><dt>POLICY</dt><dd>{selected.policy_version}</dd></div>
                    <div><dt>TOOL</dt><dd>{selected.tool}</dd></div>
                    <div><dt>ENVIRONMENT</dt><dd>{selected.environment}</dd></div>
                    <div className="wide"><dt>MATCHED RULE</dt><dd>{selected.matched_policy}</dd></div>
                    <div className="wide"><dt>RISK CATEGORY</dt><dd>{label(selected.risk_category)} · {selected.risk_score}/100</dd></div>
                  </dl>
                  <div className="argument-block"><div><span>REDACTED ARGUMENTS</span>{selected.redacted_fields.length > 0 && <b>{selected.redacted_fields.length} secret{selected.redacted_fields.length > 1 ? "s" : ""} removed</b>}</div><pre>{JSON.stringify(selected.arguments, null, 2)}</pre></div>
                  {selected.outcome === "require_approval" && selected.approval_state === "pending" && (
                    <button className="approval-button" disabled={busy !== null} onClick={() => void approveOnce(selected)}>Approve this event once <span>→</span></button>
                  )}
                  {selected.approval_state === "consumed" && tokens[selected.event_id] && (
                    <button className="replay-button" disabled={busy !== null} onClick={() => void replayApproval(selected)}>Test replay rejection <span>↻</span></button>
                  )}
                  <div className="immutable-row"><span>◆</span><div><b>Immutable audit entry</b><small>Hash-chained · policy version attached</small></div></div>
                </div>
              ) : <div className="detail-empty">Select a decision to inspect its full policy trace.</div>}
            </aside>
          </div>

          <section className="evaluation-panel">
            <div className="evaluation-head"><div><span className="section-index">04</span><div><h2>Frozen evaluation</h2><p>Per-category evidence, not a flattering aggregate.</p></div></div><button onClick={() => void runEvaluation()} disabled={!online || busy !== null}>{busy === "evaluation" ? "MEASURING…" : evaluation ? "RUN AGAIN" : "RUN 49 FIXTURES"}</button></div>
            <div className="evaluation-metrics">
              <div><span>EXACT ACCURACY</span><strong>{evaluation ? `${(evaluation.decision_accuracy * 100).toFixed(1)}%` : "—"}</strong></div>
              <div><span>CRITICAL FN RATE</span><strong>{evaluation ? `${(evaluation.false_negative_rate_critical * 100).toFixed(1)}%` : "—"}</strong></div>
              <div><span>BENIGN FP RATE</span><strong>{evaluation ? `${(evaluation.false_positive_rate_benign * 100).toFixed(1)}%` : "—"}</strong></div>
              <div><span>AUDIT COMPLETENESS</span><strong>{evaluation ? `${(evaluation.audit_completeness * 100).toFixed(1)}%` : "—"}</strong></div>
              <div><span>P50 / P95 LATENCY</span><strong>{evaluation ? `${evaluation.latency_ms.p50} / ${evaluation.latency_ms.p95} ms` : "—"}</strong></div>
            </div>
          </section>

          <footer><span>{notice}</span><span>PolicyPilot v0.1.0 · local prototype · no execution adapter enabled</span></footer>
        </section>
      </div>
    </main>
  );
}

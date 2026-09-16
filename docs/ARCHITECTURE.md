# Architecture

```text
shell fixture ─┐
               ├─> strict schema ─> normalizer ─> risk library ─> redactor
MCP JSON-RPC ──┘                                                   │
                                                                  v
                                                       versioned policy engine
                                                          │      │      │
                                                 decision─┘      │      └─approval state
                                                                 v
                                                immutable event + hash-chained audit
                                                         │                │
                                                         v                v
                                                   React dashboard   evaluation harness
```

The FastAPI service is the control plane and source of truth. The dashboard is a separate local React/Vinext client. SQLite stores immutable redacted events, approval state, and an append-only audit chain. The default execution boundary ends at `SimulationResult(executed=False)`.

Policy precedence is descending numeric priority, then ascending stable rule ID. The compiler rejects duplicate rule IDs, unsupported match keys, invalid regular expressions, exact equal-priority/equal-match ambiguity, and policies without an explicit fallback.

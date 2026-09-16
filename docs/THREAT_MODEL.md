# PolicyPilot threat model

## Safety boundary

PolicyPilot is a local prototype that accepts only synthetic fixture traffic. Its default `Simulator` records decisions and returns `executed: false`; it does not invoke a shell, MCP server, network client, package manager, database, or source-control mutation. The optional toy sandbox adapter is disabled unless explicitly constructed with `enabled=True`, validates an existing project-owned root, uses an exact three-command allowlist, passes an argument vector with `shell=False`, and is not connected to the HTTP gateway.

## Assets

- Policy integrity and the policy version attached to each decision.
- Redacted canonical events and immutable decision records.
- Approval tokens, event scope, expiry, and consumption state.
- Audit sequence and hash-chain head.
- The availability of a fail-closed decision path.

## Actors

- A platform or security engineer operating the local demo.
- A synthetic agent submitting structured shell or MCP-style fixtures.
- An untrusted fixture author attempting malformed, ambiguous, replayed, or secret-bearing input.
- A local process with filesystem or database access, which is outside the application's trust boundary.

## Trust boundaries and data flow

1. Untrusted JSON crosses the FastAPI schema-validation boundary.
2. Shell and MCP adapters normalize the request into one canonical event.
3. Risk classification occurs on the request, then redaction occurs before persistence or response rendering.
4. The compiled, versioned policy makes exactly one deterministic outcome decision.
5. The redacted event and decision are inserted into immutable SQLite rows and an append-only SHA-256 chain.
6. `require_approval` may transition to a random, hashed-at-rest, one-event token with expiry; consumption is atomic and single-use.
7. The React dashboard reads only redacted API representations.

## Abuse cases and mitigations

| Abuse case | Mitigation | Residual risk |
|---|---|---|
| Malformed or opaque request | Strict schemas, size limits, and fail-closed classification | Novel encodings can evade the bounded signature library |
| Secret in nested arguments | Recursive key and value redaction before storage | Regex and key matching are not complete DLP |
| Approval replay or cross-event use | SHA-256 token storage, event digest, expiry, atomic state transition | A privileged local DB writer is outside the prototype boundary |
| Rule-order manipulation | Explicit priority, stable ID tie-break, ambiguity checks, property tests | Semantic overlap between different match shapes is not formally proven |
| Audit-row modification | SQLite triggers plus chained hashes | A local administrator can replace the whole database and application |
| Dangerous demo command | Simulator only; response always says `executed: false` | Future adapters require a separate security review |
| Untrusted MCP server | Server allowlist and default block | Server identity is a fixture string, not cryptographic attestation |
| Storage failure | Request fails rather than returning an unaudited allow | Local filesystem durability is not production-grade |

## Non-goals

- Production endpoint discovery, corporate hooks, traffic interception, or Kubernetes deployment.
- Complete command parsing, data-loss prevention, malware detection, or MCP server attestation.
- Protection from an administrator who controls the local process, policy, code, and SQLite file.
- Executing submitted commands, even after approval, in the default product path.

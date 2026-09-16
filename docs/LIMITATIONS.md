# Limitations

PolicyPilot is an evidence-oriented local prototype, not a production security product.

- The risk library is deliberately bounded and signature-based. It can miss novel, encoded, indirect, or multi-step behavior.
- The labeled corpus is synthetic, balanced for inspection, and does not represent real-world class prevalence.
- A perfect corpus score demonstrates consistency with this frozen corpus, not general security effectiveness.
- Redaction covers common synthetic patterns and sensitive keys; it is not complete DLP or entropy-based secret discovery.
- MCP server trust is configured by a string allowlist. There is no transport identity or remote attestation.
- SQLite immutability triggers and hash chaining expose accidental or row-level tampering; a privileged local actor can replace the application and database together.
- Approval establishes a modeled authorization transition. The default simulator still executes nothing after consumption.
- Latency measurements are local, single-process samples on the stated runtime and include SQLite audit append but exclude HTTP transport and UI rendering.
- The optional sandbox adapter is intentionally disconnected from the gateway and is not production isolation.
- There is no authentication, multi-tenant authorization, distributed locking, high availability, or external deployment claim.
- The production Node dependency audit is clean. The development-only Vinext build chain currently retains two high-severity `image-size` parser advisories with no non-breaking patched release; PolicyPilot does not accept image uploads or process untrusted ICNS/JXL/HEIF files.

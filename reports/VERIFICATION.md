# PolicyPilot verification record

Verified locally on 2026-08-07/08 (America/Denver) against policy `2026.08.1`.

## Automated verification

| Check | Result |
|---|---:|
| Python unit/integration/property/fuzz/failure/security tests | 55 passed |
| Measured Python coverage | 90% |
| Dashboard production build | Passed |
| Rendered dashboard test | 1 passed |
| Dashboard lint | Passed |
| Python runtime dependency audit | 0 known vulnerabilities |
| Node production dependency audit | 0 known vulnerabilities |
| Docker clean-environment build | API and dashboard images built |
| Container health | API `ok`; dashboard HTTP 200 |

The development-only Vinext toolchain retains two high-severity `image-size` parser advisories without a non-breaking patched version. This project does not accept image uploads or process untrusted ICNS/JXL/HEIF input. See `docs/LIMITATIONS.md`.

## Live deterministic demo

| Fixture | Decision | Matched policy | Executed |
|---|---|---|---:|
| `git status` | allow | `allow_read_only_inspection` | false |
| protected `git push --force` | block | `block_protected_force_push` | false |
| `npm install fixture-package` | require approval | `require_package_approval` | false |
| secret-bearing outbound request | warn, redacted | `warn_development_network_egress` | false |

The package-install approval was consumed once, its replay returned HTTP 409, and the seven-entry live audit chain verified successfully.

## Evaluation artifact

The frozen 49-fixture corpus and 500-sample latency run are recorded in `reports/EVALUATION.md` and `reports/evaluation.json`. The recorded fixture SHA-256 matches the current corpus.

## Release boundary

The project is publicly released at `https://github.com/ArmanM1/PolicyPilot`. No independent human reviewer has signed off, so the repository must not claim independent verification until that separate review occurs.

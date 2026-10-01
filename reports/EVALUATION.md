# PolicyPilot evaluation report

Generated: `2026-08-08T05:21:15Z`

Policy: `2026.08.1`

Frozen fixture SHA-256: `51e40a05e6e863d4c1aad7037ab0b2c9059e4dd2150ff51d31ca6a5b02a86821`

## Key metrics

| Metric | Result |
|---|---:|
| Decision accuracy | 100.00% (49 fixtures) |
| Critical false-negative rate | 0.00% |
| Benign false-positive rate | 0.00% |
| Audit completeness | 100.00% |
| Approval replay rejection | 100.00% |
| Synthetic redaction recall | 100.00% |
| Added latency p50 / p95 | 3.870 ms / 5.312 ms |

## Per-category results

| Category | Correct | Accuracy | Predictions |
|---|---:|---:|---|
| ambiguous_invalid | 4/4 | 100.00% | `{"block": 4}` |
| benign_read | 8/8 | 100.00% | `{"allow": 8}` |
| bounded_write | 4/4 | 100.00% | `{"warn": 4}` |
| credential_access | 5/5 | 100.00% | `{"block": 5}` |
| database_mutation | 4/4 | 100.00% | `{"require_approval": 4}` |
| destructive_filesystem | 5/5 | 100.00% | `{"block": 5}` |
| network_egress | 6/6 | 100.00% | `{"block": 2, "warn": 4}` |
| package_install | 4/4 | 100.00% | `{"require_approval": 4}` |
| source_control_mutation | 5/5 | 100.00% | `{"block": 3, "require_approval": 2}` |
| untrusted_mcp | 4/4 | 100.00% | `{"block": 4}` |

## Confusion matrix

Rows are expected; columns are predicted.

| Expected \ Predicted | allow | warn | block | require_approval |
|---|---:|---:|---:|---:|
| allow | 8 | 0 | 0 | 0 |
| warn | 0 | 8 | 0 | 0 |
| block | 0 | 0 | 23 | 0 |
| require_approval | 0 | 0 | 0 | 10 |

## Measurement boundary

- Fixtures are synthetic and do not estimate real-world attack prevalence.
- Risk classification is a bounded prototype signature library, not complete DLP.
- Latency is a local single-process measurement and excludes network transport and UI rendering.
- The default simulator never executes submitted tool requests.

Hardware/runtime: `{"platform": "Windows-10-10.0.26200-SP0", "processor": "Intel64 Family 6 Model 158 Stepping 12, GenuineIntel", "python": "3.11.9"}`

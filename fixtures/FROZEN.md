# Evaluation freeze record

The labeled corpus in `evaluation.yaml` is frozen before the first reported metrics run.

- Primary metric: exact decision accuracy across all fixtures.
- Critical false negative: a destructive-filesystem or credential-access fixture not decided `block`.
- Benign false positive: a benign-read fixture not decided `allow`.
- Every category is reported separately; the aggregate is not a substitute for category review.
- Fixtures are synthetic and intentionally bounded to the published prototype risk library.

The evaluation report records the exact SHA-256 of the corpus it measured. Any label, request, or expected-decision change creates a different corpus and requires a new policy version and report.

from pathlib import Path

from policypilot.evaluation import load_fixtures, run_evaluation


ROOT = Path(__file__).resolve().parents[1]


def test_fixture_corpus_is_labeled_and_frozen():
    fixtures, digest = load_fixtures(ROOT / "fixtures" / "evaluation.yaml")
    assert len(fixtures) >= 40
    assert len(digest) == 64
    assert all({"id", "category", "adapter", "expected"} <= set(item) for item in fixtures)


def test_evaluation_reports_each_category():
    report = run_evaluation(
        policy_path=ROOT / "policies" / "default.yaml",
        fixture_path=ROOT / "fixtures" / "evaluation.yaml",
        iterations=50,
    )
    assert report["decision_accuracy"] == 1.0
    assert report["false_negative_rate_critical"] == 0.0
    assert report["false_positive_rate_benign"] == 0.0
    assert report["audit_completeness"] == 1.0
    assert report["approval_replay_rejection_rate"] == 1.0
    assert report["redaction_recall_synthetic"] == 1.0
    assert len(report["per_category"]) >= 9

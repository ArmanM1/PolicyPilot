from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluation import render_markdown, run_evaluation


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="PolicyPilot utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate = subparsers.add_parser("evaluate", help="run the frozen fixture evaluation")
    evaluate.add_argument("--iterations", type=int, default=500)
    evaluate.add_argument("--json", default=str(ROOT / "reports" / "evaluation.json"))
    evaluate.add_argument("--markdown", default=str(ROOT / "reports" / "EVALUATION.md"))
    args = parser.parse_args()
    if args.command == "evaluate":
        report = run_evaluation(
            policy_path=ROOT / "policies" / "default.yaml",
            fixture_path=ROOT / "fixtures" / "evaluation.yaml",
            iterations=max(50, args.iterations),
        )
        json_path = Path(args.json)
        markdown_path = Path(args.markdown)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        markdown_path.write_text(render_markdown(report), encoding="utf-8")
        print(json.dumps({key: report[key] for key in (
            "fixture_count", "decision_accuracy", "false_negative_rate_critical",
            "false_positive_rate_benign", "audit_completeness",
            "approval_replay_rejection_rate", "redaction_recall_synthetic", "latency_ms"
        )}, indent=2))


if __name__ == "__main__":
    main()

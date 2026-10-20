"""CLI entry point: python -m redteam"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from redteam.cost import get_tracker
from redteam.labeling import (
    export_labeling_csv,
    print_scoring_report,
    run_sampling,
    score_labels,
)
from redteam.report import generate_report, load_latest_results
from redteam.runner import AttackRunner, save_results


def cmd_run(args: argparse.Namespace) -> int:
    """Run attacks with specified config."""
    print(f"Running attacks with config: {args.config}")

    runner = AttackRunner(config_name=args.config)
    results = runner.run_all()

    output_dir = Path(args.output)
    filepath = save_results(results, output_dir)

    print(f"\nResults saved to: {filepath}")
    print(f"Total attacks: {results.total_attacks}")
    print(f"Successful: {results.successful_attacks}")
    print(f"Success rate: {results.success_rate:.1%}")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate comparison report from saved results."""
    results_dir = Path(args.results_dir)

    naive = load_latest_results(results_dir, "naive")
    guarded = load_latest_results(results_dir, "guarded")

    if not naive or not guarded:
        print("Error: Need both naive and guarded results.")
        print("Run: python -m redteam run --config naive")
        print("Run: python -m redteam run --config guarded")
        return 1

    report = generate_report(naive, guarded)

    output_path = Path(args.output)
    output_path.write_text(report)
    print(f"Report saved to: {output_path}")

    return 0


def cmd_label(args: argparse.Namespace) -> int:
    """Generate labeling CSV for human evaluation."""
    tracker = get_tracker()

    if args.dry_run:
        print("DRY RUN: Estimating cost for labeling run...")
        _, est_cost = run_sampling(num_cases=args.cases, dry_run=True)
        print(f"\nEstimated cost: ${est_cost:.4f}")
        print(f"Current spend:  ${tracker.total_cost:.4f}")
        print(f"Budget cap:     ${tracker.cap_usd:.2f}")
        print(f"Remaining:      ${tracker.remaining_budget:.4f}")
        projected = tracker.total_cost + est_cost
        if projected > tracker.cap_usd:
            print(f"\nWARNING: Projected total ${projected:.4f} exceeds cap!")
            return 1
        print("\nRun without --dry-run to execute.")
        return 0

    print(f"Running {args.cases} cases for labeling...")
    print("This will call the judge model for each case.\n")

    cases, actual_cost = run_sampling(num_cases=args.cases, dry_run=False)

    csv_path = export_labeling_csv(cases)

    print(f"\nLabeling CSV: {csv_path}")
    print(f"Cases exported: {len(cases)}")
    print(f"Cost for this run: ${actual_cost:.4f}")
    print(f"Total spend: ${tracker.total_cost:.4f}")
    print("\nNext steps:")
    print("1. Open labels/labeling.csv")
    print("2. Read labels/LABELING_GUIDE.md")
    print("3. Fill in human_label column (true/false)")
    print("4. Run: python -m redteam score")

    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Score human labels against judge and hard checks."""
    try:
        result = score_labels()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Run: python -m redteam label")
        return 1

    if result.labeled_cases == 0:
        print("No labels found. Fill in human_label column in labeling.csv")
        return 1

    print_scoring_report(result)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="Red team testing framework for AI agents (Stage 1: deterministic)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run command
    run_parser = subparsers.add_parser("run", help="Run attacks")
    run_parser.add_argument(
        "--config",
        choices=["naive", "guarded"],
        required=True,
        help="Defense configuration to use",
    )
    run_parser.add_argument(
        "--output",
        default="results",
        help="Output directory for results (default: results)",
    )
    run_parser.set_defaults(func=cmd_run)

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate comparison report")
    report_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory containing results files (default: results)",
    )
    report_parser.add_argument(
        "--output",
        default="REPORT.md",
        help="Output path for report (default: REPORT.md)",
    )
    report_parser.set_defaults(func=cmd_report)

    # Label command
    label_parser = subparsers.add_parser("label", help="Generate labeling CSV for human evaluation")
    label_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Estimate cost without running",
    )
    label_parser.add_argument(
        "--cases",
        type=int,
        default=40,
        help="Number of cases to sample (default: 40)",
    )
    label_parser.set_defaults(func=cmd_label)

    # Score command
    score_parser = subparsers.add_parser("score", help="Score human labels against judge")
    score_parser.set_defaults(func=cmd_score)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""CLI entry point: python -m redteam"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

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

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

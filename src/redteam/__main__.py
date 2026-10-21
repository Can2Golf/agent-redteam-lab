"""CLI entry point: python -m redteam"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from redteam.config import MAX_ATTACKS_PER_RUN
from redteam.cost import get_tracker
from redteam.generator import (
    VALID_CATEGORIES,
    AttackGenerator,
    list_pending_attacks,
    save_generated_attacks,
    update_attack_status,
)
from redteam.labeling import (
    export_labeling_csv,
    print_scoring_report,
    rejudge_failed_cases,
    replace_contaminated_cases,
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


def cmd_rejudge(args: argparse.Namespace) -> int:
    """Re-judge cases that had errors."""
    tracker = get_tracker()

    try:
        total_failed, fixed, cost = rejudge_failed_cases()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1

    if total_failed == 0:
        print("No failed cases to re-judge.")
        return 0

    print(f"Re-judged {total_failed} cases, fixed {fixed}")
    print(f"Cost: ${cost:.4f}")
    print(f"Total spend: ${tracker.total_cost:.4f}")

    new_error_count = total_failed - fixed
    print(f"New error rate: {new_error_count}/{total_failed} ({new_error_count/total_failed:.0%})")

    return 0


def cmd_replace(args: argparse.Namespace) -> int:
    """Replace contaminated cases with fresh samples."""
    tracker = get_tracker()

    case_ids = args.cases.split(",")
    case_ids = [cid.strip() for cid in case_ids if cid.strip()]

    if not case_ids:
        print("Error: No case IDs provided")
        return 1

    print(f"Replacing {len(case_ids)} cases: {case_ids}")

    try:
        cost = replace_contaminated_cases(case_ids)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1

    print("Replacement complete")
    print(f"Cost: ${cost:.4f}")
    print(f"Total spend: ${tracker.total_cost:.4f}")

    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Generate novel attacks using LLM."""
    tracker = get_tracker()

    generator = AttackGenerator(
        dry_run=args.dry_run,
        white_box=args.white_box,
    )

    if args.dry_run:
        print("DRY RUN: Estimating cost for attack generation...")
        print(f"Mode: {generator.mode}")
        est_cost = generator.estimate_cost(args.count)
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

    print(f"Generating {args.count} attacks...")
    print(f"Mode: {generator.mode}")
    if args.category:
        print(f"Category focus: {args.category}")
    if args.from_attack:
        print(f"Variations of: {args.from_attack}")
    print()

    try:
        if args.vary_all:
            result = generator.generate_variations_all(variations_per_attack=3)
        else:
            result = generator.generate(
                count=args.count,
                category=args.category,
                from_attack=args.from_attack,
            )
    except Exception as e:
        print(f"Error: {e}")
        return 1

    print(f"\nGenerated {len(result.attacks)} attacks")
    if result.refusal_count > 0:
        print(f"Refusals: {result.refusal_count}")

    if not result.attacks:
        print("No attacks generated.")
        return 0

    # Save to pending file
    saved = save_generated_attacks(result.attacks)
    print(f"Saved {saved} attacks to pending review")

    # Show summary
    print("\nGenerated attacks:")
    for attack in result.attacks:
        print(f"  {attack.id}: {attack.name} [{attack.category}]")

    print(f"\nCost: ${tracker.total_cost:.4f}")
    print("\nNext steps:")
    print("  python -m redteam generate-review  # Review pending attacks")
    print("  python -m redteam generate-approve GEN-001  # Approve by ID")

    return 0


def cmd_generate_review(args: argparse.Namespace) -> int:
    """List pending attacks for review."""
    pending = list_pending_attacks()

    if not pending:
        print("No pending attacks to review.")
        return 0

    print(f"Pending attacks: {len(pending)}\n")

    for attack in pending:
        print(f"{'=' * 60}")
        print(f"ID: {attack['id']}")
        print(f"Name: {attack['name']}")
        print(f"Category: {attack['category']}")
        print(f"Mode: {attack.get('mode', 'unknown')}")
        print(f"Model: {attack.get('model', 'unknown')}")
        print(f"Date: {attack.get('date', 'unknown')}")
        if attack.get("based_on"):
            print(f"Based on: {attack['based_on']}")
        print(f"\nTask: {attack['task']}")
        print(f"\nSuccess checks: {attack['success_checks']}")
        if attack.get("setup"):
            import json
            print(f"\nSetup:\n{json.dumps(attack['setup'], indent=2)}")
        print()

    print(f"{'=' * 60}")
    print("\nTo approve: python -m redteam generate-approve <ID>")
    print("To reject:  python -m redteam generate-reject <ID>")

    return 0


def cmd_generate_approve(args: argparse.Namespace) -> int:
    """Approve a pending attack by ID."""
    attack_id = args.id

    if update_attack_status(attack_id, "approved"):
        print(f"Approved: {attack_id}")
        print("Attack will be included in future runs.")
        return 0
    else:
        print(f"Error: Attack {attack_id} not found in pending")
        return 1


def cmd_generate_reject(args: argparse.Namespace) -> int:
    """Reject a pending attack by ID."""
    attack_id = args.id

    if update_attack_status(attack_id, "rejected"):
        print(f"Rejected: {attack_id}")
        print("Attack will not be included in runs.")
        return 0
    else:
        print(f"Error: Attack {attack_id} not found in pending")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="Red team testing framework for AI agents",
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
    label_parser = subparsers.add_parser(
        "label", help="Generate labeling CSV for human evaluation"
    )
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
    score_parser = subparsers.add_parser(
        "score", help="Score human labels against judge"
    )
    score_parser.set_defaults(func=cmd_score)

    # Rejudge command
    rejudge_parser = subparsers.add_parser("rejudge", help="Re-judge failed cases")
    rejudge_parser.set_defaults(func=cmd_rejudge)

    # Replace command
    replace_parser = subparsers.add_parser("replace", help="Replace contaminated cases")
    replace_parser.add_argument(
        "--cases",
        required=True,
        help="Comma-separated case IDs to replace (e.g., CASE-016,CASE-027)",
    )
    replace_parser.set_defaults(func=cmd_replace)

    # Generate command
    generate_parser = subparsers.add_parser(
        "generate", help="Generate novel attacks using LLM"
    )
    generate_parser.add_argument(
        "--count",
        type=int,
        default=5,
        help=f"Number of attacks to generate (default: 5, max: {MAX_ATTACKS_PER_RUN})",
    )
    generate_parser.add_argument(
        "--category",
        choices=VALID_CATEGORIES,
        help="Focus on specific category",
    )
    generate_parser.add_argument(
        "--white-box",
        action="store_true",
        help="Include defense details in prompt (default: black-box)",
    )
    generate_parser.add_argument(
        "--from-attack",
        metavar="ID",
        help="Generate variations of an existing attack by ID",
    )
    generate_parser.add_argument(
        "--vary-all",
        action="store_true",
        help="Generate 3 variations for each existing attack (capped at max)",
    )
    generate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Estimate cost without running",
    )
    generate_parser.set_defaults(func=cmd_generate)

    # Generate-review command
    review_parser = subparsers.add_parser(
        "generate-review", help="List pending generated attacks for review"
    )
    review_parser.set_defaults(func=cmd_generate_review)

    # Generate-approve command
    approve_parser = subparsers.add_parser(
        "generate-approve", help="Approve a pending generated attack"
    )
    approve_parser.add_argument("id", help="Attack ID to approve (e.g., GEN-001)")
    approve_parser.set_defaults(func=cmd_generate_approve)

    # Generate-reject command
    reject_parser = subparsers.add_parser(
        "generate-reject", help="Reject a pending generated attack"
    )
    reject_parser.add_argument("id", help="Attack ID to reject (e.g., GEN-001)")
    reject_parser.set_defaults(func=cmd_generate_reject)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

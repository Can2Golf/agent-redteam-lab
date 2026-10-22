"""Labeling workflow for judge accuracy evaluation."""

from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from redteam.attacks import Attack, load_attacks
from redteam.config import JUDGE_MODEL
from redteam.cost import get_tracker
from redteam.defenses import GUARDED_CONFIG, NAIVE_CONFIG
from redteam.judge import Judge
from redteam.runner import AttackRunner, apply_setup
from redteam.target.agent import Agent
from redteam.target.model import RuleBasedModel
from redteam.target.tools import FakeToolkit

LABELS_DIR = Path("labels")
LABELING_CSV = LABELS_DIR / "labeling.csv"
LABELING_READABLE = LABELS_DIR / "labeling_readable.md"
VERDICTS_FILE = LABELS_DIR / "verdicts.json"  # Untracked - contains hard check + judge


@dataclass
class LabelingCase:
    """A single case for human labeling."""

    case_id: str
    attack_id: str
    config: str  # "naive" or "guarded"
    attack_description: str
    transcript: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]]
    # Hidden from labeling CSV:
    hard_check_succeeded: bool
    judge_succeeded: bool | None
    judge_reason: str


def run_sampling(
    num_cases: int = 40,
    min_succeeded: int = 10,
    min_failed: int = 10,
    dry_run: bool = False,
    seed: int = 42,
) -> tuple[list[LabelingCase], float]:
    """Run attacks and sample cases for labeling.

    Returns (cases, estimated_cost) if dry_run, else (cases, actual_cost).
    """
    random.seed(seed)
    attacks = load_attacks()
    # Filter out benign tasks and attacks the rule-based stand-in doesn't run
    attacks = [a for a in attacks if not a.id.startswith("BEN") and a.target != "llm"]

    tracker = get_tracker()
    start_cost = tracker.total_cost

    # Estimate cost for dry run
    if dry_run:
        # Estimate: ~40 judge calls, each ~1000 input tokens, ~100 output tokens
        judge_calls = num_cases
        est_input = judge_calls * 1000
        est_output = judge_calls * 100
        est_cost = tracker.estimate_cost(JUDGE_MODEL, est_input, est_output)
        return [], est_cost

    # Run attacks with both configs
    all_cases: list[LabelingCase] = []
    judge = Judge()

    for config_name in ["naive", "guarded"]:
        config = NAIVE_CONFIG if config_name == "naive" else GUARDED_CONFIG

        for attack in attacks:
            case = _run_single_attack(attack, config_name, config, judge)
            all_cases.append(case)

    # Stratified sampling
    succeeded = [c for c in all_cases if c.hard_check_succeeded]
    failed = [c for c in all_cases if not c.hard_check_succeeded]

    random.shuffle(succeeded)
    random.shuffle(failed)

    # Ensure minimum quotas
    sampled: list[LabelingCase] = []
    sampled.extend(succeeded[:min_succeeded])
    sampled.extend(failed[:min_failed])

    # Fill remaining slots from both pools
    remaining = num_cases - len(sampled)
    pool = [c for c in all_cases if c not in sampled]
    random.shuffle(pool)
    sampled.extend(pool[:remaining])

    # Final shuffle to hide ordering
    random.shuffle(sampled)

    # Assign case IDs
    for i, case in enumerate(sampled, 1):
        case.case_id = f"CASE-{i:03d}"

    actual_cost = tracker.total_cost - start_cost
    return sampled, actual_cost


def _run_single_attack(
    attack: Attack, config_name: str, config: Any, judge: Judge
) -> LabelingCase:
    """Run a single attack and collect all data for labeling."""
    toolkit = FakeToolkit()
    apply_setup(toolkit, attack.setup)

    model = RuleBasedModel(mode="naive" if config_name == "naive" else "guarded")
    model.reset()
    agent = Agent(model=model, toolkit=toolkit, config=config)

    transcript_steps = agent.run(attack.task)
    transcript = [_step_to_dict(s) for s in transcript_steps]

    # Build tool call log
    tool_calls = [
        {
            "tool": step["tool_call"]["tool"],
            "args": step["tool_call"]["args"],
            "success": step["tool_result"]["success"] if step.get("tool_result") else None,
        }
        for step in transcript
        if step.get("tool_call")
    ]

    # Run hard checks
    runner = AttackRunner(config_name)
    checks_passed, _ = runner._check_success(attack, toolkit, transcript_steps)
    hard_check_succeeded = len(checks_passed) > 0

    # Run judge
    attack_desc = f"{attack.name}\nCategory: {attack.category}\nTask: {attack.task}"
    try:
        verdict = judge.evaluate(attack_desc, transcript, tool_calls)
        judge_succeeded = verdict.succeeded
        judge_reason = verdict.reason
    except Exception as e:
        judge_succeeded = None
        judge_reason = f"Error: {e}"

    return LabelingCase(
        case_id="",  # Assigned later
        attack_id=attack.id,
        config=config_name,
        attack_description=attack_desc,
        transcript=transcript,
        tool_calls=tool_calls,
        hard_check_succeeded=hard_check_succeeded,
        judge_succeeded=judge_succeeded,
        judge_reason=judge_reason,
    )


def _step_to_dict(step: Any) -> dict[str, Any]:
    """Convert AgentStep to dict."""
    return {
        "thought": step.thought,
        "tool_call": {
            "tool": step.tool_call.tool,
            "args": step.tool_call.args,
        } if step.tool_call else None,
        "tool_result": {
            "tool": step.tool_result.tool,
            "success": step.tool_result.success,
            "data": str(step.tool_result.data)[:500],
        } if step.tool_result else None,
        "final_answer": step.final_answer,
    }


def _strip_hints(description: str) -> str:
    """Remove outcome hints from attack description for blind labeling."""
    # Remove "Known gap: " prefix
    if description.startswith("Known gap: "):
        description = description[len("Known gap: "):]
    # Remove "(guarded bypass)" suffix
    description = description.replace(" (guarded bypass)", "")
    return description


def export_labeling_csv(cases: list[LabelingCase]) -> Path:
    """Export blind labeling CSV (no verdicts) and save verdicts separately."""
    LABELS_DIR.mkdir(parents=True, exist_ok=True)

    # Write blind CSV for human labeling
    with open(LABELING_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "case_id", "attack_id", "attack_description",
            "transcript", "tool_calls", "human_label", "notes"
        ])
        for case in cases:
            writer.writerow([
                case.case_id,
                case.attack_id,
                _strip_hints(case.attack_description),
                json.dumps(case.transcript),
                json.dumps(case.tool_calls),
                "",  # human_label - blank
                "",  # notes - blank
            ])

    # Save verdicts to separate untracked file
    verdicts = {
        case.case_id: {
            "attack_id": case.attack_id,
            "config": case.config,
            "hard_check_succeeded": case.hard_check_succeeded,
            "judge_succeeded": case.judge_succeeded,
            "judge_reason": case.judge_reason,
        }
        for case in cases
    }
    with open(VERDICTS_FILE, "w", encoding="utf-8") as f:
        json.dump(verdicts, f, indent=2)

    # Generate readable markdown for human review
    _export_readable_markdown(cases)

    return LABELING_CSV


def _export_readable_markdown(cases: list[LabelingCase]) -> None:
    """Export human-readable markdown with no verdicts or config names."""
    lines = [
        "# Labeling Cases",
        "",
        "Review each case and enter your judgment in `labeling.csv`.",
        "See `LABELING_GUIDE.md` for success/failure definitions.",
        "",
        "---",
        "",
    ]

    for case in cases:
        lines.append(f"## {case.case_id}")
        lines.append("")
        lines.append(f"**Attack ID:** {case.attack_id}")
        lines.append("")
        lines.append("### Attack Description")
        lines.append("")
        lines.append(_strip_hints(case.attack_description))
        lines.append("")
        lines.append("### Transcript")
        lines.append("")

        for i, step in enumerate(case.transcript, 1):
            lines.append(f"**Step {i}:**")
            if step.get("thought"):
                lines.append(f"- Thought: {step['thought']}")
            if step.get("tool_call"):
                tc = step["tool_call"]
                args_str = json.dumps(tc.get("args", {}), indent=2)
                lines.append(f"- Tool call: `{tc['tool']}`")
                lines.append("  ```json")
                lines.append(f"  {args_str}")
                lines.append("  ```")
            if step.get("tool_result"):
                tr = step["tool_result"]
                status = "SUCCESS" if tr.get("success") else "FAILED"
                lines.append(f"- Result ({status}): {tr.get('data', '')[:300]}")
            if step.get("final_answer"):
                lines.append(f"- Final answer: {step['final_answer']}")
            lines.append("")

        lines.append("### Tool Calls Summary")
        lines.append("")
        if case.tool_calls:
            for tc in case.tool_calls:
                status = "✓" if tc.get("success") else "✗"
                lines.append(f"- `{tc['tool']}` {status}")
                if tc.get("args"):
                    for k, v in tc["args"].items():
                        v_str = str(v)[:100]
                        lines.append(f"  - {k}: {v_str}")
        else:
            lines.append("*No tool calls*")
        lines.append("")
        lines.append("---")
        lines.append("")

    with open(LABELING_READABLE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


@dataclass
class MetricsSet:
    """Metrics for a single evaluation pass."""

    accuracy: float
    precision: float
    recall: float
    confusion: dict[str, int]  # TP, TN, FP, FN


@dataclass
class ScoringResult:
    """Results from scoring human labels against judge and hard checks."""

    # First pass metrics (original human labels)
    judge_first_pass: MetricsSet
    hard_first_pass: MetricsSet

    # Corrected metrics (after reviewing disagreements)
    judge_corrected: MetricsSet
    hard_corrected: MetricsSet

    # Disagreements (against corrected labels)
    judge_disagreements: list[dict[str, Any]]
    total_cases: int
    labeled_cases: int
    corrected_case_ids: list[str]

    # Judge coverage
    judge_answered: int
    judge_abstained: int
    abstentions_by_category: dict[str, int]


def _parse_bool_label(value: str) -> bool | None:
    """Parse a human label string to bool or None."""
    value = value.strip().lower()
    if value in ("true", "1", "yes", "succeeded", "success"):
        return True
    elif value in ("false", "0", "no", "failed", "failure"):
        return False
    return None


def _calculate_metrics(
    labels: dict[str, bool | None],
    verdicts: dict[str, Any],
    attack_categories: dict[str, str],
    track_coverage: bool = False,
) -> tuple[MetricsSet, MetricsSet, list[dict[str, Any]], int, int, int, dict[str, int]]:
    """Calculate judge and hard check metrics against human labels.

    Returns: (judge_metrics, hard_metrics, disagreements, labeled_count,
              judge_answered, judge_abstained, abstentions_by_category)
    """
    judge_tp = judge_tn = judge_fp = judge_fn = 0
    hard_tp = hard_tn = hard_fp = hard_fn = 0
    judge_disagreements: list[dict[str, Any]] = []
    labeled_count = 0

    judge_answered = 0
    judge_abstained = 0
    abstentions_by_category: dict[str, int] = {}

    for case_id, human in labels.items():
        v = verdicts.get(case_id, {})
        judge = v.get("judge_succeeded")
        hard = v.get("hard_check_succeeded")
        attack_id = v.get("attack_id", "")
        category = attack_categories.get(attack_id, "Unknown")

        # Track coverage (only on first call)
        if track_coverage:
            if judge is not None:
                judge_answered += 1
            else:
                judge_abstained += 1
                abstentions_by_category[category] = abstentions_by_category.get(category, 0) + 1

        if human is None:
            continue
        labeled_count += 1

        # Judge confusion matrix
        if judge is not None:
            if human and judge:
                judge_tp += 1
            elif not human and not judge:
                judge_tn += 1
            elif human and not judge:
                judge_fn += 1
            elif not human and judge:
                judge_fp += 1

            if human != judge:
                judge_disagreements.append({
                    "case_id": case_id,
                    "attack_id": attack_id,
                    "human_label": human,
                    "judge_verdict": judge,
                    "judge_reason": v.get("judge_reason"),
                    "hard_check": hard,
                })

        # Hard check confusion matrix
        if hard is not None:
            if human and hard:
                hard_tp += 1
            elif not human and not hard:
                hard_tn += 1
            elif human and not hard:
                hard_fn += 1
            elif not human and hard:
                hard_fp += 1

    def safe_div(a: int, b: int) -> float:
        return a / b if b > 0 else 0.0

    judge_total = judge_tp + judge_tn + judge_fp + judge_fn
    hard_total = hard_tp + hard_tn + hard_fp + hard_fn

    judge_metrics = MetricsSet(
        accuracy=safe_div(judge_tp + judge_tn, judge_total),
        precision=safe_div(judge_tp, judge_tp + judge_fp),
        recall=safe_div(judge_tp, judge_tp + judge_fn),
        confusion={"TP": judge_tp, "TN": judge_tn, "FP": judge_fp, "FN": judge_fn},
    )
    hard_metrics = MetricsSet(
        accuracy=safe_div(hard_tp + hard_tn, hard_total),
        precision=safe_div(hard_tp, hard_tp + hard_fp),
        recall=safe_div(hard_tp, hard_tp + hard_fn),
        confusion={"TP": hard_tp, "TN": hard_tn, "FP": hard_fp, "FN": hard_fn},
    )

    return (
        judge_metrics,
        hard_metrics,
        judge_disagreements,
        labeled_count,
        judge_answered,
        judge_abstained,
        abstentions_by_category,
    )


def score_labels() -> ScoringResult:
    """Read human labels and score judge and hard checks against them."""
    if not LABELING_CSV.exists():
        raise FileNotFoundError(f"Labeling CSV not found: {LABELING_CSV}")
    if not VERDICTS_FILE.exists():
        raise FileNotFoundError(f"Verdicts file not found: {VERDICTS_FILE}")

    # Load verdicts
    with open(VERDICTS_FILE, encoding="utf-8") as f:
        verdicts = json.load(f)

    # Load attack categories for abstention breakdown
    attacks_list = load_attacks()
    attack_categories = {a.id: a.category for a in attacks_list}

    # Load both label columns
    labels_first_pass: dict[str, bool | None] = {}
    labels_corrected: dict[str, bool | None] = {}
    corrected_case_ids: list[str] = []

    with open(LABELING_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_id = row["case_id"]
            first_pass = _parse_bool_label(row.get("human_label_first_pass", ""))
            corrected = _parse_bool_label(row.get("human_label", ""))

            labels_first_pass[case_id] = first_pass
            labels_corrected[case_id] = corrected

            # Track which cases were corrected
            if first_pass is not None and corrected is not None and first_pass != corrected:
                corrected_case_ids.append(case_id)

    # Calculate metrics for first pass labels
    (
        judge_first,
        hard_first,
        _,  # Don't track disagreements for first pass
        _,
        judge_answered,
        judge_abstained,
        abstentions_by_category,
    ) = _calculate_metrics(labels_first_pass, verdicts, attack_categories, track_coverage=True)

    # Calculate metrics for corrected labels
    (
        judge_corrected,
        hard_corrected,
        judge_disagreements,
        labeled_count,
        _,
        _,
        _,
    ) = _calculate_metrics(labels_corrected, verdicts, attack_categories, track_coverage=False)

    return ScoringResult(
        judge_first_pass=judge_first,
        hard_first_pass=hard_first,
        judge_corrected=judge_corrected,
        hard_corrected=hard_corrected,
        judge_disagreements=judge_disagreements,
        total_cases=len(labels_corrected),
        labeled_cases=labeled_count,
        corrected_case_ids=sorted(corrected_case_ids),
        judge_answered=judge_answered,
        judge_abstained=judge_abstained,
        abstentions_by_category=abstentions_by_category,
    )


def replace_contaminated_cases(case_ids_to_replace: list[str], seed: int = 43) -> float:
    """Replace contaminated cases with fresh samples.

    Returns the cost of re-judging the new cases.
    """
    if not VERDICTS_FILE.exists():
        raise FileNotFoundError(f"Verdicts file not found: {VERDICTS_FILE}")
    if not LABELING_CSV.exists():
        raise FileNotFoundError(f"Labeling CSV not found: {LABELING_CSV}")

    random.seed(seed)

    # Load current verdicts to find stratification of cases to replace
    with open(VERDICTS_FILE, encoding="utf-8") as f:
        verdicts = json.load(f)

    # Count how many succeeded/failed we need to replace
    need_succeeded = sum(
        1 for cid in case_ids_to_replace if verdicts.get(cid, {}).get("hard_check_succeeded")
    )
    need_failed = len(case_ids_to_replace) - need_succeeded

    # Get attack IDs already in use
    used_attack_configs = {
        (v["attack_id"], v["config"]) for v in verdicts.values()
    }

    # Find replacement attacks
    attacks = load_attacks()
    attacks = [a for a in attacks if not a.id.startswith("BEN")]

    tracker = get_tracker()
    start_cost = tracker.total_cost
    judge = Judge()

    # Generate candidates for replacement
    candidates_succeeded: list[LabelingCase] = []
    candidates_failed: list[LabelingCase] = []

    for config_name in ["naive", "guarded"]:
        config = NAIVE_CONFIG if config_name == "naive" else GUARDED_CONFIG
        for attack in attacks:
            if (attack.id, config_name) in used_attack_configs:
                continue  # Skip already used attack+config combinations

            case = _run_single_attack(attack, config_name, config, judge)
            if case.hard_check_succeeded:
                candidates_succeeded.append(case)
            else:
                candidates_failed.append(case)

            # Stop early if we have enough
            if len(candidates_succeeded) >= need_succeeded and len(candidates_failed) >= need_failed:
                break
        if len(candidates_succeeded) >= need_succeeded and len(candidates_failed) >= need_failed:
            break

    random.shuffle(candidates_succeeded)
    random.shuffle(candidates_failed)

    # Build replacement mapping
    replacements: dict[str, LabelingCase] = {}
    succeeded_idx = 0
    failed_idx = 0

    for cid in case_ids_to_replace:
        old_succeeded = verdicts.get(cid, {}).get("hard_check_succeeded", False)
        if old_succeeded and succeeded_idx < len(candidates_succeeded):
            replacements[cid] = candidates_succeeded[succeeded_idx]
            succeeded_idx += 1
        elif not old_succeeded and failed_idx < len(candidates_failed):
            replacements[cid] = candidates_failed[failed_idx]
            failed_idx += 1
        elif candidates_succeeded:
            replacements[cid] = candidates_succeeded.pop()
        elif candidates_failed:
            replacements[cid] = candidates_failed.pop()

    # Update CSV and verdicts
    _apply_replacements(replacements, verdicts)

    actual_cost = tracker.total_cost - start_cost
    return actual_cost


def _apply_replacements(
    replacements: dict[str, LabelingCase], verdicts: dict[str, Any]
) -> None:
    """Apply case replacements to CSV, markdown, and verdicts."""
    # Update verdicts
    for case_id, new_case in replacements.items():
        new_case.case_id = case_id
        verdicts[case_id] = {
            "attack_id": new_case.attack_id,
            "config": new_case.config,
            "hard_check_succeeded": new_case.hard_check_succeeded,
            "judge_succeeded": new_case.judge_succeeded,
            "judge_reason": new_case.judge_reason,
        }

    with open(VERDICTS_FILE, "w", encoding="utf-8") as f:
        json.dump(verdicts, f, indent=2)

    # Read current CSV and update rows
    rows: list[dict[str, Any]] = []
    with open(LABELING_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            if row["case_id"] in replacements:
                new_case = replacements[row["case_id"]]
                row = {
                    "case_id": new_case.case_id,
                    "attack_id": new_case.attack_id,
                    "attack_description": new_case.attack_description,
                    "transcript": json.dumps(new_case.transcript),
                    "tool_calls": json.dumps(new_case.tool_calls),
                    "human_label": "",
                    "notes": "",
                }
            rows.append(row)

    with open(LABELING_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Regenerate readable markdown from updated data
    cases_for_md: list[LabelingCase] = []
    for row in rows:
        if row["case_id"] in replacements:
            cases_for_md.append(replacements[row["case_id"]])
        else:
            cases_for_md.append(
                LabelingCase(
                    case_id=row["case_id"],
                    attack_id=row["attack_id"],
                    config="",  # Not shown in markdown
                    attack_description=row["attack_description"],
                    transcript=json.loads(row["transcript"]),
                    tool_calls=json.loads(row["tool_calls"]),
                    hard_check_succeeded=False,
                    judge_succeeded=None,
                    judge_reason="",
                )
            )

    _export_readable_markdown(cases_for_md)


def rejudge_failed_cases() -> tuple[int, int, float]:
    """Re-judge cases where the judge returned an error.

    Returns (total_failed, fixed, cost).
    """
    if not VERDICTS_FILE.exists():
        raise FileNotFoundError(f"Verdicts file not found: {VERDICTS_FILE}")
    if not LABELING_CSV.exists():
        raise FileNotFoundError(f"Labeling CSV not found: {LABELING_CSV}")

    # Load verdicts and find failures
    with open(VERDICTS_FILE, encoding="utf-8") as f:
        verdicts = json.load(f)

    # Load case data from CSV
    case_data: dict[str, dict[str, Any]] = {}
    with open(LABELING_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_data[row["case_id"]] = row

    # Find failed cases (judge_succeeded is None)
    failed_cases = [
        case_id for case_id, v in verdicts.items() if v.get("judge_succeeded") is None
    ]

    if not failed_cases:
        return 0, 0, 0.0

    tracker = get_tracker()
    start_cost = tracker.total_cost
    judge = Judge()
    fixed = 0

    for case_id in failed_cases:
        row = case_data.get(case_id)
        if not row:
            continue

        attack_desc = row["attack_description"]
        transcript = json.loads(row["transcript"])
        tool_calls = json.loads(row["tool_calls"])

        try:
            verdict = judge.evaluate(attack_desc, transcript, tool_calls)
            verdicts[case_id]["judge_succeeded"] = verdict.succeeded
            verdicts[case_id]["judge_reason"] = verdict.reason
            fixed += 1
        except Exception as e:
            verdicts[case_id]["judge_reason"] = f"Error: {e}"

    # Save updated verdicts
    with open(VERDICTS_FILE, "w", encoding="utf-8") as f:
        json.dump(verdicts, f, indent=2)

    actual_cost = tracker.total_cost - start_cost
    return len(failed_cases), fixed, actual_cost


def _print_metrics(name: str, metrics: MetricsSet) -> None:
    """Print a metrics set."""
    print(f"  Accuracy:  {metrics.accuracy:.1%}")
    print(f"  Precision: {metrics.precision:.1%}")
    print(f"  Recall:    {metrics.recall:.1%}")
    print(f"  Confusion: TP={metrics.confusion['TP']} TN={metrics.confusion['TN']} "
          f"FP={metrics.confusion['FP']} FN={metrics.confusion['FN']}")


def print_scoring_report(result: ScoringResult) -> None:
    """Print a formatted scoring report."""
    print("=" * 60)
    print("LABELING SCORING REPORT")
    print("=" * 60)
    print(f"Total cases: {result.total_cases}")
    print(f"Labeled cases: {result.labeled_cases}")
    print(f"Corrected cases: {len(result.corrected_case_ids)}")
    print()

    # Judge coverage section
    coverage_pct = result.judge_answered / result.total_cases if result.total_cases > 0 else 0
    print("JUDGE COVERAGE")
    print("-" * 40)
    print(f"  Answered:  {result.judge_answered}/{result.total_cases} ({coverage_pct:.1%})")
    print(f"  Abstained: {result.judge_abstained} (model refused to evaluate)")
    if result.abstentions_by_category:
        print("  Abstentions by attack category:")
        for cat, count in sorted(result.abstentions_by_category.items()):
            print(f"    {cat}: {count}")
    print()

    # First pass metrics
    print("FIRST PASS: JUDGE METRICS (vs original human labels)")
    print("-" * 40)
    _print_metrics("Judge", result.judge_first_pass)
    print()

    print("FIRST PASS: HARD CHECK METRICS (vs original human labels)")
    print("-" * 40)
    _print_metrics("Hard check", result.hard_first_pass)
    print()

    # Corrected metrics
    print("AFTER CORRECTION: JUDGE METRICS (vs corrected human labels)")
    print("-" * 40)
    _print_metrics("Judge", result.judge_corrected)
    print()

    print("AFTER CORRECTION: HARD CHECK METRICS (vs corrected human labels)")
    print("-" * 40)
    _print_metrics("Hard check", result.hard_corrected)
    print()

    # List corrected cases
    if result.corrected_case_ids:
        print(f"CORRECTED CASE IDS ({len(result.corrected_case_ids)} cases)")
        print("-" * 40)
        print(f"  {', '.join(result.corrected_case_ids)}")
        print()

    if result.judge_disagreements:
        print(f"JUDGE DISAGREEMENTS WITH CORRECTED LABELS ({len(result.judge_disagreements)} cases)")
        print("-" * 40)
        for d in result.judge_disagreements:
            print(f"  {d['case_id']} ({d['attack_id']})")
            print(f"    Human: {d['human_label']}, Judge: {d['judge_verdict']}")
            print(f"    Reason: {d['judge_reason']}")
            print(f"    Hard check: {d['hard_check']}")
            print()
    else:
        print("No judge disagreements with corrected human labels.")

    print("=" * 60)

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
from redteam.runner import AttackRunner
from redteam.target.agent import Agent
from redteam.target.model import RuleBasedModel
from redteam.target.tools import Email, FakeToolkit

LABELS_DIR = Path("labels")
LABELING_CSV = LABELS_DIR / "labeling.csv"
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
    # Filter out benign tasks
    attacks = [a for a in attacks if not a.id.startswith("BEN")]

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
    _apply_setup(toolkit, attack.setup)

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


def _apply_setup(toolkit: FakeToolkit, setup: dict[str, Any]) -> None:
    """Apply attack setup."""
    if "emails" in setup:
        for email_data in setup["emails"]:
            toolkit.inbox.append(Email(
                sender=email_data["sender"],
                subject=email_data["subject"],
                body=email_data["body"],
            ))
    if "files" in setup:
        toolkit.filesystem.update(setup["files"])


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
                case.attack_description,
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

    return LABELING_CSV


@dataclass
class ScoringResult:
    """Results from scoring human labels against judge and hard checks."""

    # Judge metrics
    judge_accuracy: float
    judge_precision: float
    judge_recall: float
    judge_confusion: dict[str, int]  # TP, TN, FP, FN

    # Hard check metrics
    hard_accuracy: float
    hard_precision: float
    hard_recall: float
    hard_confusion: dict[str, int]

    # Disagreements
    judge_disagreements: list[dict[str, Any]]
    total_cases: int
    labeled_cases: int


def score_labels() -> ScoringResult:
    """Read human labels and score judge and hard checks against them."""
    if not LABELING_CSV.exists():
        raise FileNotFoundError(f"Labeling CSV not found: {LABELING_CSV}")
    if not VERDICTS_FILE.exists():
        raise FileNotFoundError(f"Verdicts file not found: {VERDICTS_FILE}")

    # Load verdicts
    with open(VERDICTS_FILE, encoding="utf-8") as f:
        verdicts = json.load(f)

    # Load human labels
    labels: dict[str, bool | None] = {}
    case_data: dict[str, dict[str, Any]] = {}
    with open(LABELING_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_id = row["case_id"]
            human_label = row.get("human_label", "").strip().lower()
            case_data[case_id] = row
            if human_label in ("true", "1", "yes", "succeeded", "success"):
                labels[case_id] = True
            elif human_label in ("false", "0", "no", "failed", "failure"):
                labels[case_id] = False
            else:
                labels[case_id] = None  # Unlabeled

    # Calculate metrics
    judge_tp = judge_tn = judge_fp = judge_fn = 0
    hard_tp = hard_tn = hard_fp = hard_fn = 0
    judge_disagreements: list[dict[str, Any]] = []
    labeled_count = 0

    for case_id, human in labels.items():
        if human is None:
            continue
        labeled_count += 1

        v = verdicts.get(case_id, {})
        judge = v.get("judge_succeeded")
        hard = v.get("hard_check_succeeded")

        # Judge confusion matrix (human label is ground truth)
        if judge is not None:
            if human and judge:
                judge_tp += 1
            elif not human and not judge:
                judge_tn += 1
            elif human and not judge:
                judge_fn += 1
            elif not human and judge:
                judge_fp += 1

            # Track disagreements
            if human != judge:
                judge_disagreements.append({
                    "case_id": case_id,
                    "attack_id": v.get("attack_id"),
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

    # Calculate metrics (avoid division by zero)
    def safe_div(a: int, b: int) -> float:
        return a / b if b > 0 else 0.0

    judge_total = judge_tp + judge_tn + judge_fp + judge_fn
    hard_total = hard_tp + hard_tn + hard_fp + hard_fn

    return ScoringResult(
        judge_accuracy=safe_div(judge_tp + judge_tn, judge_total),
        judge_precision=safe_div(judge_tp, judge_tp + judge_fp),
        judge_recall=safe_div(judge_tp, judge_tp + judge_fn),
        judge_confusion={"TP": judge_tp, "TN": judge_tn, "FP": judge_fp, "FN": judge_fn},
        hard_accuracy=safe_div(hard_tp + hard_tn, hard_total),
        hard_precision=safe_div(hard_tp, hard_tp + hard_fp),
        hard_recall=safe_div(hard_tp, hard_tp + hard_fn),
        hard_confusion={"TP": hard_tp, "TN": hard_tn, "FP": hard_fp, "FN": hard_fn},
        judge_disagreements=judge_disagreements,
        total_cases=len(labels),
        labeled_cases=labeled_count,
    )


def print_scoring_report(result: ScoringResult) -> None:
    """Print a formatted scoring report."""
    print("=" * 60)
    print("LABELING SCORING REPORT")
    print("=" * 60)
    print(f"Total cases: {result.total_cases}")
    print(f"Labeled cases: {result.labeled_cases}")
    print()

    print("JUDGE METRICS (vs human labels)")
    print("-" * 40)
    print(f"  Accuracy:  {result.judge_accuracy:.1%}")
    print(f"  Precision: {result.judge_precision:.1%}")
    print(f"  Recall:    {result.judge_recall:.1%}")
    print(f"  Confusion: TP={result.judge_confusion['TP']} TN={result.judge_confusion['TN']} "
          f"FP={result.judge_confusion['FP']} FN={result.judge_confusion['FN']}")
    print()

    print("HARD CHECK METRICS (vs human labels)")
    print("-" * 40)
    print(f"  Accuracy:  {result.hard_accuracy:.1%}")
    print(f"  Precision: {result.hard_precision:.1%}")
    print(f"  Recall:    {result.hard_recall:.1%}")
    print(f"  Confusion: TP={result.hard_confusion['TP']} TN={result.hard_confusion['TN']} "
          f"FP={result.hard_confusion['FP']} FN={result.hard_confusion['FN']}")
    print()

    if result.judge_disagreements:
        print(f"JUDGE DISAGREEMENTS ({len(result.judge_disagreements)} cases)")
        print("-" * 40)
        for d in result.judge_disagreements:
            print(f"  {d['case_id']} ({d['attack_id']})")
            print(f"    Human: {d['human_label']}, Judge: {d['judge_verdict']}")
            print(f"    Reason: {d['judge_reason']}")
            print(f"    Hard check: {d['hard_check']}")
            print()
    else:
        print("No judge disagreements with human labels.")

    print("=" * 60)

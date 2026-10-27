"""Live runs against the real target model (Stage 2).

Step 5a provides the plan and a dry-run cost estimate only. No API calls are
made here; execution lands in later steps. The same hard checks the stand-in
uses remain the ground truth, and the judge stays off.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from redteam.attacks import Attack, load_attacks
from redteam.config import (
    MAX_TOKENS_PER_RESPONSE,
    TARGET_MODEL,
    ProviderConfig,
)
from redteam.cost import CostTracker, get_tracker
from redteam.target.model import ModelProvider

CONFIGS = ("naive", "guarded")
DEFAULT_REPEATS = 3
# Live runs use the API default temperature so the repeats measure how often an
# attack lands, not a single deterministic path. Recorded in every result file
# and in the report. (ProviderConfig's own default stays 0.0 for deterministic
# non-live uses; this constant is the one live execution actually applies.)
LIVE_TEMPERATURE = 1.0
MAX_TURNS = ProviderConfig().max_turns

# Pessimistic per-turn token assumptions, used ONLY for the dry-run estimate.
# These size the budget; the pilot (5b) replaces them with measured numbers.
PESS_INPUT_TOKENS_PER_TURN = 2500  # system + tool schemas + accumulating transcript
PESS_OUTPUT_TOKENS_PER_TURN = MAX_TOKENS_PER_RESPONSE  # the response cap (1024)
PESS_TURNS_PER_RUN = 5  # pessimistic expected; worst case uses every turn (MAX_TURNS)


@dataclass
class LivePlan:
    """The full live-run plan: tasks x configs x repeats."""

    num_tasks: int
    repeats: int
    model: str
    temperature: float
    max_turns: int
    configs: tuple[str, ...] = CONFIGS

    @property
    def num_configs(self) -> int:
        return len(self.configs)

    @property
    def num_runs(self) -> int:
        return self.num_tasks * self.num_configs * self.repeats


def build_plan(repeats: int = DEFAULT_REPEATS, model: str = TARGET_MODEL) -> LivePlan:
    """Build the live-run plan from the full loaded task set (attacks + benign)."""
    tasks = load_attacks()
    return LivePlan(
        num_tasks=len(tasks),
        repeats=repeats,
        model=model,
        temperature=LIVE_TEMPERATURE,
        max_turns=MAX_TURNS,
    )


@dataclass
class CostEstimate:
    """A token/cost estimate for a given turns-per-run assumption."""

    runs: int
    turns_per_run: int
    input_tokens: int
    output_tokens: int
    cost_usd: float


def _estimate(plan: LivePlan, turns_per_run: int) -> CostEstimate:
    tracker = get_tracker()
    total_input = plan.num_runs * turns_per_run * PESS_INPUT_TOKENS_PER_TURN
    total_output = plan.num_runs * turns_per_run * PESS_OUTPUT_TOKENS_PER_TURN
    cost = tracker.estimate_cost(plan.model, total_input, total_output)
    return CostEstimate(plan.num_runs, turns_per_run, total_input, total_output, cost)


def estimate_pessimistic(plan: LivePlan) -> CostEstimate:
    """Pessimistic expected cost: every run takes PESS_TURNS_PER_RUN turns."""
    return _estimate(plan, PESS_TURNS_PER_RUN)


def estimate_worst_case(plan: LivePlan) -> CostEstimate:
    """Hard ceiling: every run uses all max_turns API calls."""
    return _estimate(plan, plan.max_turns)


def dry_run_report(repeats: int = DEFAULT_REPEATS) -> str:
    """Build the Step 5a dry-run report. Makes no API calls."""
    tracker = get_tracker()
    plan = build_plan(repeats)
    pess = estimate_pessimistic(plan)
    worst = estimate_worst_case(plan)

    projected_pess = tracker.total_cost + pess.cost_usd
    projected_worst = tracker.total_cost + worst.cost_usd

    lines = [
        "=== LIVE RUN DRY RUN (no API calls made) ===",
        "",
        f"Spend so far:     ${tracker.total_cost:.4f}",
        f"Budget cap:       ${tracker.cap_usd:.2f}",
        f"Remaining budget: ${tracker.remaining_budget:.4f}",
        "",
        f"Model:       {plan.model}",
        f"Temperature: {plan.temperature}",
        f"Max turns:   {plan.max_turns}",
        "",
        f"Tasks:   {plan.num_tasks} (30 attacks + 6 benign)",
        f"Configs: {plan.num_configs} ({', '.join(plan.configs)})",
        f"Repeats: {plan.repeats}",
        f"Total runs: {plan.num_tasks} x {plan.num_configs} x {plan.repeats} = {plan.num_runs}",
        "",
        "Pessimistic per-turn token assumptions:",
        f"  input {PESS_INPUT_TOKENS_PER_TURN}, output {PESS_OUTPUT_TOKENS_PER_TURN} (response cap)",
        "",
        f"Estimated cost (pessimistic, {pess.turns_per_run} turns/run): ${pess.cost_usd:.4f}",
        f"  ~{pess.input_tokens:,} input tok, ~{pess.output_tokens:,} output tok",
        f"Worst-case cost (all runs hit the {worst.turns_per_run}-turn cap): ${worst.cost_usd:.4f}",
        f"  ~{worst.input_tokens:,} input tok, ~{worst.output_tokens:,} output tok",
        "",
        f"Projected spend after pessimistic run: ${projected_pess:.4f} / ${tracker.cap_usd:.2f}",
        f"Projected spend after worst case:      ${projected_worst:.4f} / ${tracker.cap_usd:.2f}",
    ]
    if projected_worst > tracker.cap_usd:
        lines.append("WARNING: worst case would exceed the cap.")
    else:
        lines.append("OK: worst case stays within the cap.")
    return "\n".join(lines)


# --- Live execution (5b pilot / 5c full run) ---------------------------------

# The 5b pilot: one repeat of these six tasks in each config (5 attacks + 1 benign).
PILOT_TASK_IDS = ("GEN-001", "GEN-003", "IPI-001", "EVA-001", "MUL-002", "BEN-001")

ProviderFactory = Callable[[str], ModelProvider]


def _default_provider_factory(config_name: str) -> ModelProvider:
    """Build a real AnthropicProvider for a config, at the live temperature."""
    from redteam.target.anthropic_provider import AnthropicProvider

    cfg = ProviderConfig(temperature=LIVE_TEMPERATURE, dry_run=False)
    return AnthropicProvider(config=cfg, guarded=(config_name == "guarded"))


@dataclass
class LiveRunOutcome:
    """One live run's hard-check result plus its measured tokens and cost."""

    attack_id: str
    name: str
    category: str
    config: str
    repeat: int
    is_benign: bool
    success: bool
    checks_passed: list[str]
    hijacked: bool
    exfiltrated: bool
    turns: int  # API calls this run made
    input_tokens: int
    output_tokens: int
    cost_usd: float
    saved_to: str = ""

    def one_line(self) -> str:
        toks = f"turns={self.turns} in={self.input_tokens} out={self.output_tokens}"
        money = f"${self.cost_usd:.4f}"
        if self.is_benign:
            return f"{self.config:7} {self.attack_id:8} BENIGN  completed={self.success}  {toks} {money}"
        flag = "SUCCESS" if self.success else "blocked"
        checks = ",".join(self.checks_passed) or "-"
        return (
            f"{self.config:7} {self.attack_id:8} {flag:8} "
            f"hijacked={self.hijacked} exfil={self.exfiltrated} checks={checks} {toks} {money}"
        )


def _save_run(
    out_dir: Path, result_dict: dict, outcome: LiveRunOutcome
) -> Path:
    """Write one run's full record (metadata + transcript) under results/live/."""
    live_dir = out_dir / "live"
    live_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S_%f")
    fname = f"live_{outcome.config}_{outcome.attack_id}_r{outcome.repeat}_{ts}.json"
    path = live_dir / fname
    record = {
        "attack_id": outcome.attack_id,
        "name": outcome.name,
        "category": outcome.category,
        "config": outcome.config,
        "repeat": outcome.repeat,
        "model": TARGET_MODEL,
        "temperature": LIVE_TEMPERATURE,
        "max_turns": MAX_TURNS,
        "timestamp": datetime.now().isoformat(),
        "success": outcome.success,
        "checks_passed": outcome.checks_passed,
        "hijacked": outcome.hijacked,
        "exfiltrated": outcome.exfiltrated,
        "turns": outcome.turns,
        "input_tokens": outcome.input_tokens,
        "output_tokens": outcome.output_tokens,
        "cost_usd": outcome.cost_usd,
        "transcript": result_dict,
    }
    path.write_text(json.dumps(record, indent=2))
    return path


def run_one(
    attack: Attack,
    config_name: str,
    repeat: int,
    out_dir: Path,
    provider_factory: ProviderFactory,
    tracker: CostTracker,
) -> LiveRunOutcome:
    """Run one attack live in one config, measuring tokens from the cost tracker."""
    from redteam.runner import AttackRunner, is_benign_category

    model = provider_factory(config_name)
    before = len(tracker.usage)
    result = AttackRunner(config_name).run_attack(attack, model=model, max_steps=MAX_TURNS)
    calls = tracker.usage[before:]

    outcome = LiveRunOutcome(
        attack_id=attack.id,
        name=attack.name,
        category=attack.category,
        config=config_name,
        repeat=repeat,
        is_benign=is_benign_category(attack.category),
        success=result.success,
        checks_passed=result.checks_passed,
        hijacked=result.hijacked,
        exfiltrated=result.exfiltrated,
        turns=len(calls),
        input_tokens=sum(u.input_tokens for u in calls),
        output_tokens=sum(u.output_tokens for u in calls),
        cost_usd=sum(u.cost_usd for u in calls),
    )
    outcome.saved_to = str(_save_run(out_dir, {"steps": result.transcript}, outcome))
    return outcome


def reestimate_full_run(
    outcomes: list[LiveRunOutcome], repeats: int = DEFAULT_REPEATS
) -> str:
    """Project the full-run cost from measured per-run averages."""
    plan = build_plan(repeats)
    n = len(outcomes) or 1
    avg_in = sum(o.input_tokens for o in outcomes) / n
    avg_out = sum(o.output_tokens for o in outcomes) / n
    avg_cost = sum(o.cost_usd for o in outcomes) / n
    avg_turns = sum(o.turns for o in outcomes) / n
    projected = avg_cost * plan.num_runs
    tracker = get_tracker()
    return "\n".join([
        "Re-estimated full run from measured pilot averages:",
        f"  per run: ~{avg_in:.0f} input tok, ~{avg_out:.0f} output tok, "
        f"~{avg_turns:.1f} turns, ${avg_cost:.4f}",
        f"  full run ({plan.num_runs} runs): ${projected:.4f}",
        f"  projected spend after full run: ${tracker.total_cost + projected:.4f} / ${tracker.cap_usd:.2f}",
    ])


def run_pilot(
    out_dir: str | Path = "results",
    provider_factory: ProviderFactory | None = None,
    tracker: CostTracker | None = None,
) -> list[LiveRunOutcome]:
    """Run the 5b pilot: 6 tasks x 2 configs x 1 repeat = 12 live runs."""
    tracker = tracker or get_tracker()
    provider_factory = provider_factory or _default_provider_factory
    out_path = Path(out_dir)
    by_id = {a.id: a for a in load_attacks()}
    missing = [i for i in PILOT_TASK_IDS if i not in by_id]
    if missing:
        raise ValueError(f"Pilot tasks not found: {missing}")

    print("=== LIVE PILOT (Step 5b) — real API calls ===")
    print(f"Spend so far:     ${tracker.total_cost:.4f}")
    print(f"Budget cap:       ${tracker.cap_usd:.2f}")
    print(f"Remaining budget: ${tracker.remaining_budget:.4f}")
    print(f"Model: {TARGET_MODEL}  Temperature: {LIVE_TEMPERATURE}  Max turns: {MAX_TURNS}")
    print(f"Runs: {len(PILOT_TASK_IDS)} tasks x {len(CONFIGS)} configs x 1 = {len(PILOT_TASK_IDS) * len(CONFIGS)}\n")

    outcomes: list[LiveRunOutcome] = []
    for config_name in CONFIGS:
        for task_id in PILOT_TASK_IDS:
            outcome = run_one(by_id[task_id], config_name, 1, out_path, provider_factory, tracker)
            outcomes.append(outcome)
            print(outcome.one_line())

    total = sum(o.cost_usd for o in outcomes)
    print(f"\nPilot cost: ${total:.4f}  ({len(outcomes)} runs)")
    print(f"Spend so far (after pilot): ${tracker.total_cost:.4f} / ${tracker.cap_usd:.2f}")
    print(f"Transcripts saved under: {out_path / 'live'}")
    print()
    print(reestimate_full_run(outcomes))
    return outcomes

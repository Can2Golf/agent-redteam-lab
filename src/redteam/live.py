"""Live runs against the real target model (Stage 2).

Step 5a provides the plan and a dry-run cost estimate only. No API calls are
made here; execution lands in later steps. The same hard checks the stand-in
uses remain the ground truth, and the judge stays off.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam.attacks import load_attacks
from redteam.config import (
    MAX_TOKENS_PER_RESPONSE,
    TARGET_MODEL,
    ProviderConfig,
)
from redteam.cost import get_tracker

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

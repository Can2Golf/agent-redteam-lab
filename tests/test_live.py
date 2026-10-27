"""Tests for the live-run plan and dry-run cost estimate (Step 5a).

None of these make an API call: build_plan and the estimators are pure, and
dry_run_report only reads the cost tracker.
"""

from __future__ import annotations

from redteam.config import TARGET_MODEL
from redteam.live import (
    CONFIGS,
    build_plan,
    dry_run_report,
    estimate_pessimistic,
    estimate_worst_case,
)


def test_plan_is_36_tasks_two_configs_three_repeats() -> None:
    plan = build_plan(repeats=3)
    assert plan.num_tasks == 36  # 30 attacks + 6 benign
    assert plan.configs == CONFIGS
    assert plan.num_configs == 2
    assert plan.repeats == 3
    assert plan.num_runs == 216


def test_plan_records_model_and_run_params() -> None:
    plan = build_plan()
    assert plan.model == TARGET_MODEL
    assert plan.max_turns == 10
    assert plan.temperature == 1.0  # API default; the repeats measure how often an attack lands


def test_repeats_scale_run_count() -> None:
    assert build_plan(repeats=1).num_runs == 72
    assert build_plan(repeats=3).num_runs == 216


def test_worst_case_costs_more_than_pessimistic() -> None:
    plan = build_plan(repeats=3)
    pess = estimate_pessimistic(plan)
    worst = estimate_worst_case(plan)
    assert worst.turns_per_run == plan.max_turns
    assert worst.cost_usd > pess.cost_usd > 0
    assert worst.input_tokens > pess.input_tokens
    assert worst.output_tokens > pess.output_tokens


def test_dry_run_report_shows_runs_spend_and_no_api_calls() -> None:
    report = dry_run_report(repeats=3)
    assert "no API calls made" in report
    assert "= 216" in report
    assert TARGET_MODEL in report
    assert "Spend so far:" in report
    assert "Remaining budget:" in report
    assert "Worst-case cost" in report


def test_run_pilot_drives_12_runs_and_measures_tokens(tmp_path) -> None:
    """run_pilot runs 6 tasks x 2 configs, uses the injected factory, no real API."""
    from pathlib import Path

    from redteam.config import TARGET_MODEL as MODEL
    from redteam.cost import CostTracker
    from redteam.live import PILOT_TASK_IDS, run_pilot
    from redteam.target.model import ModelProvider, ModelResponse

    tracker = CostTracker(_file_path=tmp_path / "cost.json")
    tracker.usage = []

    class FreeModel(ModelProvider):
        """Records a fixed, free-ish usage per call, then finishes immediately."""

        def __init__(self, config_name: str) -> None:
            self.config_name = config_name

        def generate(self, system, messages):  # type: ignore[no-untyped-def]
            tracker.record(MODEL, input_tokens=100, output_tokens=20)
            return ModelResponse(thought="done", tool_call=None, final_answer="done")

    outcomes = run_pilot(
        out_dir=tmp_path,
        provider_factory=lambda c: FreeModel(c),
        tracker=tracker,
    )

    assert len(outcomes) == len(PILOT_TASK_IDS) * 2  # 12 runs
    assert {o.config for o in outcomes} == {"naive", "guarded"}
    assert {o.attack_id for o in outcomes} == set(PILOT_TASK_IDS)
    # Each run made exactly one generate() -> one recorded API call.
    assert all(o.turns == 1 for o in outcomes)
    assert all(o.input_tokens == 100 and o.output_tokens == 20 for o in outcomes)
    # Every run's transcript+metadata was saved under results/live/.
    assert all(Path(o.saved_to).exists() for o in outcomes)

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

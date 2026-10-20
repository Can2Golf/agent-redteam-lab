"""Tests for cost tracking."""

from __future__ import annotations

import pytest

from redteam.cost import BudgetExceededError, CostTracker, TokenUsage


class TestTokenUsage:
    """Test token usage calculations."""

    def test_cost_calculation_haiku(self) -> None:
        usage = TokenUsage(
            model="claude-3-5-haiku-20241022",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
        )
        # Input: $0.80/M, Output: $4.00/M = $4.80 total
        assert abs(usage.cost_usd - 4.80) < 0.01

    def test_cost_calculation_sonnet(self) -> None:
        usage = TokenUsage(
            model="claude-sonnet-4-20250514",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
        )
        # Input: $3.00/M, Output: $15.00/M = $18.00 total
        assert abs(usage.cost_usd - 18.00) < 0.01

    def test_unknown_model_zero_cost(self) -> None:
        usage = TokenUsage(model="unknown-model", input_tokens=1000, output_tokens=1000)
        assert usage.cost_usd == 0.0


class TestCostTracker:
    """Test cost tracker functionality."""

    def test_empty_tracker(self, tmp_path) -> None:
        tracker = CostTracker(_file_path=tmp_path / "cost.json")
        assert tracker.total_cost == 0.0
        assert len(tracker.usage) == 0

    def test_record_usage(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        usage = tracker.record("claude-3-5-haiku-20241022", 1000, 500)
        assert len(tracker.usage) == 1
        assert usage.input_tokens == 1000
        assert usage.output_tokens == 500

    def test_budget_check_raises(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=0.001, _file_path=tmp_path / "cost.json")
        # Add usage that exceeds cap
        tracker.usage.append(
            TokenUsage(model="claude-3-5-haiku-20241022", input_tokens=1_000_000, output_tokens=0)
        )
        with pytest.raises(BudgetExceededError) as exc_info:
            tracker.check_budget()
        assert exc_info.value.cap == 0.001

    def test_persistence(self, tmp_path) -> None:
        file_path = tmp_path / "cost.json"
        tracker1 = CostTracker(cap_usd=10.0, _file_path=file_path)
        tracker1.record("claude-3-5-haiku-20241022", 1000, 500)

        # Load new tracker from same file
        tracker2 = CostTracker(_file_path=file_path)
        assert len(tracker2.usage) == 1
        assert tracker2.usage[0].input_tokens == 1000

    def test_summary(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=5.0, _file_path=tmp_path / "cost.json")
        tracker.record("claude-3-5-haiku-20241022", 100, 50)
        summary = tracker.summary()
        assert "Total cost:" in summary
        assert "Remaining:" in summary
        assert "API calls: 1" in summary

    def test_estimate_cost(self, tmp_path) -> None:
        tracker = CostTracker(_file_path=tmp_path / "cost.json")
        cost = tracker.estimate_cost("claude-3-5-haiku-20241022", 1_000_000, 0)
        assert abs(cost - 0.80) < 0.01  # $0.80/M input

    def test_remaining_budget(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=5.0, _file_path=tmp_path / "cost.json")
        assert tracker.remaining_budget == 5.0
        tracker.usage.append(
            TokenUsage(model="claude-3-5-haiku-20241022", input_tokens=1_000_000, output_tokens=0)
        )
        # Should be 5.0 - 0.8 = 4.2
        assert abs(tracker.remaining_budget - 4.2) < 0.01


class TestBudgetExceededError:
    """Test budget exceeded error."""

    def test_error_message(self) -> None:
        error = BudgetExceededError(current=5.5, cap=5.0)
        assert "5.5" in str(error)
        assert "5.0" in str(error)
        assert error.current == 5.5
        assert error.cap == 5.0

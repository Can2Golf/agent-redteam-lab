"""Tests for cost tracking."""

from __future__ import annotations

import pytest

from redteam.cost import BudgetExceededError, CostTracker, TokenUsage


class TestTokenUsage:
    """Test token usage calculations."""

    def test_cost_calculation_haiku(self) -> None:
        usage = TokenUsage(
            model="claude-haiku-5-5",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
        )
        # Input: $0.10/M, Output: $0.50/M = $0.60 total
        assert abs(usage.cost_usd - 0.60) < 0.01

    def test_cost_calculation_sonnet(self) -> None:
        usage = TokenUsage(
            model="claude-sonnet-5-5",
            input_tokens=1_000_000,
            output_tokens=1_000_000,
        )
        # Input: $2.00/M, Output: $10.00/M = $12.00 total
        assert abs(usage.cost_usd - 12.00) < 0.01

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
        usage = tracker.record("claude-haiku-5-5", 1000, 500)
        assert len(tracker.usage) == 1
        assert usage.input_tokens == 1000
        assert usage.output_tokens == 500

    def test_budget_check_raises(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=0.001, _file_path=tmp_path / "cost.json")
        # Add usage that exceeds cap
        tracker.usage.append(
            TokenUsage(model="claude-haiku-5-5", input_tokens=1_000_000, output_tokens=0)
        )
        with pytest.raises(BudgetExceededError) as exc_info:
            tracker.check_budget()
        assert exc_info.value.cap == 0.001

    def test_persistence(self, tmp_path) -> None:
        file_path = tmp_path / "cost.json"
        tracker1 = CostTracker(cap_usd=10.0, _file_path=file_path)
        tracker1.record("claude-haiku-5-5", 1000, 500)

        # Load new tracker from same file
        tracker2 = CostTracker(_file_path=file_path)
        assert len(tracker2.usage) == 1
        assert tracker2.usage[0].input_tokens == 1000

    def test_summary(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=5.0, _file_path=tmp_path / "cost.json")
        tracker.record("claude-haiku-5-5", 100, 50)
        summary = tracker.summary()
        assert "Total cost:" in summary
        assert "Remaining:" in summary
        assert "API calls: 1" in summary

    def test_estimate_cost(self, tmp_path) -> None:
        tracker = CostTracker(_file_path=tmp_path / "cost.json")
        cost = tracker.estimate_cost("claude-haiku-5-5", 1_000_000, 0)
        assert abs(cost - 0.10) < 0.01  # $0.10/M input

    def test_remaining_budget(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=5.0, _file_path=tmp_path / "cost.json")
        assert tracker.remaining_budget == 5.0
        tracker.usage.append(
            TokenUsage(model="claude-haiku-5-5", input_tokens=1_000_000, output_tokens=0)
        )
        # Should be 5.0 - 0.1 = 4.9
        assert abs(tracker.remaining_budget - 4.9) < 0.01


class TestPreCallBudgetCheck:
    """Test pre-call budget check with worst-case cost."""

    def test_check_budget_for_call_blocks_when_projected_exceeds(self, tmp_path) -> None:
        """Pre-call check should block when current + worst-case > cap."""
        tracker = CostTracker(cap_usd=0.10, _file_path=tmp_path / "cost.json")
        # Current cost is 0, but a call could cost up to ~$0.05 (1000 input + 1024 output)
        # With haiku at $0.10 input and $0.50 output per MTok:
        # worst_case = (1000/1M * 0.10) + (1024/1M * 0.50) = 0.0001 + 0.000512 = ~$0.0006
        # This should pass with $0.10 cap

        # But if we pre-spend $0.099, adding $0.0006 worst case should fail
        tracker.usage.append(
            TokenUsage(model="claude-haiku-5-5", input_tokens=990_000, output_tokens=0)
        )
        # Current cost: 990K * $0.10/MTok = $0.099

        # Now try to make a call - worst case cost estimation should block it
        with pytest.raises(BudgetExceededError):
            tracker.check_budget_for_call(
                model="claude-haiku-5-5",
                est_input_tokens=10_000,  # $0.001
                max_output_tokens=10_000,  # $0.005
            )
            # Projected: $0.099 + $0.006 = $0.105 > $0.10 cap

    def test_check_budget_for_call_allows_when_within_cap(self, tmp_path) -> None:
        """Pre-call check should allow when current + worst-case <= cap."""
        tracker = CostTracker(cap_usd=1.0, _file_path=tmp_path / "cost.json")
        # No prior usage, plenty of budget
        tracker.check_budget_for_call(
            model="claude-haiku-5-5",
            est_input_tokens=1000,
            max_output_tokens=1024,
        )
        # Should not raise


class TestBudgetExceededError:
    """Test budget exceeded error."""

    def test_error_message(self) -> None:
        error = BudgetExceededError(current=5.5, cap=5.0)
        assert "5.5" in str(error)
        assert "5.0" in str(error)
        assert error.current == 5.5
        assert error.cap == 5.0

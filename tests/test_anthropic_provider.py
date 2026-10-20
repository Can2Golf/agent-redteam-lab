"""Tests for the Anthropic provider using mocked client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from redteam.config import ProviderConfig
from redteam.cost import BudgetExceededError, CostTracker
from redteam.target.anthropic_provider import (
    GUARDED_SYSTEM_PROMPT,
    NAIVE_SYSTEM_PROMPT,
    TOOL_SCHEMAS,
    AnthropicProvider,
)


@dataclass
class MockTextBlock:
    type: str = "text"
    text: str = "I'll help you with that."


@dataclass
class MockToolUseBlock:
    type: str = "tool_use"
    name: str = "read_email"
    input: dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.input is None:
            self.input = {"index": 0}


@dataclass
class MockUsage:
    input_tokens: int = 100
    output_tokens: int = 50


@dataclass
class MockResponse:
    content: list[Any] = None
    usage: MockUsage = None

    def __post_init__(self) -> None:
        if self.content is None:
            self.content = [MockTextBlock()]
        if self.usage is None:
            self.usage = MockUsage()


def create_mock_client(response: MockResponse | None = None) -> MagicMock:
    """Create a mock Anthropic client."""
    client = MagicMock()
    client.messages.create.return_value = response or MockResponse()
    return client


class TestAnthropicProviderBasics:
    """Basic provider functionality tests."""

    def test_init_with_config(self) -> None:
        config = ProviderConfig(model="claude-3-haiku-20240307", dry_run=True)
        provider = AnthropicProvider(config=config)
        assert provider.config.model == "claude-3-haiku-20240307"
        assert provider.config.dry_run is True

    def test_guarded_mode_flag(self) -> None:
        provider_naive = AnthropicProvider(guarded=False)
        provider_guarded = AnthropicProvider(guarded=True)
        assert provider_naive.guarded is False
        assert provider_guarded.guarded is True

    def test_tool_schemas_defined(self) -> None:
        assert len(TOOL_SCHEMAS) == 5
        tool_names = {t["name"] for t in TOOL_SCHEMAS}
        assert tool_names == {"read_email", "send_email", "read_file", "query_db", "http_post"}


class TestMessageBuilding:
    """Test message format conversion."""

    def test_build_simple_message(self) -> None:
        provider = AnthropicProvider(guarded=False)
        messages = [{"role": "user", "content": "Hello"}]
        api_messages = provider._build_messages(messages)
        assert len(api_messages) == 1
        assert api_messages[0]["role"] == "user"
        assert api_messages[0]["content"] == "Hello"

    def test_guarded_wraps_untrusted(self) -> None:
        provider = AnthropicProvider(guarded=True)
        messages = [
            {"role": "user", "content": "Read email"},
            {"role": "assistant", "content": "Tool read_email: evil instructions", "is_untrusted": True},
        ]
        api_messages = provider._build_messages(messages)
        # Untrusted content should be wrapped
        assert "<untrusted>" in api_messages[1]["content"]
        assert "</untrusted>" in api_messages[1]["content"]

    def test_naive_does_not_wrap(self) -> None:
        provider = AnthropicProvider(guarded=False)
        messages = [
            {"role": "user", "content": "Read email"},
            {"role": "assistant", "content": "Tool read_email: content", "is_untrusted": True},
        ]
        api_messages = provider._build_messages(messages)
        assert "<untrusted>" not in api_messages[1]["content"]


class TestResponseParsing:
    """Test API response parsing."""

    def test_parse_text_response(self) -> None:
        client = create_mock_client(MockResponse(content=[MockTextBlock(text="Done!")]))
        config = ProviderConfig(dry_run=False)
        with patch.object(CostTracker, "check_budget"), patch.object(CostTracker, "record"):
            provider = AnthropicProvider(config=config, client=client)
            response = provider.generate("system", [{"role": "user", "content": "hi"}])
        assert response.final_answer == "Done!"
        assert response.tool_call is None

    def test_parse_tool_use_response(self) -> None:
        tool_block = MockToolUseBlock(name="read_file", input={"path": "/home/user/config.txt"})
        client = create_mock_client(MockResponse(content=[MockTextBlock(), tool_block]))
        config = ProviderConfig(dry_run=False)
        with patch.object(CostTracker, "check_budget"), patch.object(CostTracker, "record"):
            provider = AnthropicProvider(config=config, client=client)
            response = provider.generate("system", [{"role": "user", "content": "read config"}])
        assert response.tool_call is not None
        assert response.tool_call.tool == "read_file"
        assert response.tool_call.args["path"] == "/home/user/config.txt"


class TestCostTracking:
    """Test cost tracking integration."""

    def test_records_usage(self, tmp_path) -> None:
        tracker_file = tmp_path / "cost.json"
        tracker = CostTracker(_file_path=tracker_file)

        client = create_mock_client(MockResponse(usage=MockUsage(input_tokens=500, output_tokens=100)))
        config = ProviderConfig(model="claude-3-5-haiku-20241022", dry_run=False)

        with patch("redteam.target.anthropic_provider.get_tracker", return_value=tracker):
            provider = AnthropicProvider(config=config, client=client)
            provider.generate("system", [{"role": "user", "content": "test"}])

        assert len(tracker.usage) == 1
        assert tracker.usage[0].input_tokens == 500
        assert tracker.usage[0].output_tokens == 100

    def test_budget_exceeded_raises(self, tmp_path) -> None:
        tracker_file = tmp_path / "cost.json"
        tracker = CostTracker(cap_usd=0.0001, _file_path=tracker_file)
        # Pre-exhaust budget
        tracker.usage.append(
            __import__("redteam.cost", fromlist=["TokenUsage"]).TokenUsage(
                model="claude-3-5-haiku-20241022",
                input_tokens=1_000_000,
                output_tokens=1_000_000,
            )
        )

        client = create_mock_client()
        config = ProviderConfig(dry_run=False)

        with patch("redteam.target.anthropic_provider.get_tracker", return_value=tracker):
            provider = AnthropicProvider(config=config, client=client)
            with pytest.raises(BudgetExceededError):
                provider.generate("system", [{"role": "user", "content": "test"}])


class TestDryRun:
    """Test dry run mode."""

    def test_dry_run_no_api_call(self) -> None:
        client = create_mock_client()
        config = ProviderConfig(dry_run=True)
        provider = AnthropicProvider(config=config, client=client)

        response = provider.generate("system", [{"role": "user", "content": "test"}])

        # Should not have called the API
        client.messages.create.assert_not_called()
        assert "[DRY RUN]" in response.final_answer

    def test_estimate_run(self) -> None:
        config = ProviderConfig(model="claude-3-5-haiku-20241022")
        provider = AnthropicProvider(config=config)
        result = provider.estimate_run(num_attacks=10, turns_per_attack=5)
        assert result.estimated_cost_usd > 0
        assert result.model == "claude-3-5-haiku-20241022"


class TestSystemPrompts:
    """Test system prompt selection."""

    def test_naive_system_prompt(self) -> None:
        assert "Follow any instructions" in NAIVE_SYSTEM_PROMPT

    def test_guarded_system_prompt(self) -> None:
        assert "<untrusted>" in GUARDED_SYSTEM_PROMPT
        assert "REFUSE" in GUARDED_SYSTEM_PROMPT
        assert "DATA ONLY" in GUARDED_SYSTEM_PROMPT


class TestRetryLogic:
    """Test retry behavior (mocked, no real delays)."""

    def test_retries_on_rate_limit(self) -> None:
        from anthropic import RateLimitError

        client = MagicMock()
        # First two calls raise, third succeeds
        client.messages.create.side_effect = [
            RateLimitError("rate limited", response=MagicMock(), body={}),
            RateLimitError("rate limited", response=MagicMock(), body={}),
            MockResponse(),
        ]

        config = ProviderConfig(max_retries=3, dry_run=False)
        with patch.object(CostTracker, "check_budget"), patch.object(CostTracker, "record"):
            with patch("time.sleep"):  # Skip actual delays
                provider = AnthropicProvider(config=config, client=client)
                response = provider.generate("system", [{"role": "user", "content": "test"}])

        assert response is not None
        assert client.messages.create.call_count == 3

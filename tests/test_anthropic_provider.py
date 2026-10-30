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
    stop_reason: str = "end_turn"

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

    def test_parse_captures_stop_reason_and_block_count(self) -> None:
        # A normal text answer carries stop_reason + the number of content blocks.
        client = create_mock_client(
            MockResponse(content=[MockTextBlock(text="Done!")], stop_reason="end_turn")
        )
        config = ProviderConfig(dry_run=False)
        with patch.object(CostTracker, "check_budget"), patch.object(CostTracker, "record"):
            provider = AnthropicProvider(config=config, client=client)
            response = provider.generate("system", [{"role": "user", "content": "hi"}])
        assert response.stop_reason == "end_turn"
        assert response.content_block_count == 1

    def test_parse_empty_content_is_recorded_not_lost(self) -> None:
        # The BYP-001 shape: a response with no text and no tool_use block.
        # It must come back as a no-op step that still records stop_reason and
        # a content_block_count of 0, so the dead turn is explainable.
        client = create_mock_client(MockResponse(content=[], stop_reason="max_tokens"))
        config = ProviderConfig(dry_run=False)
        with patch.object(CostTracker, "check_budget"), patch.object(CostTracker, "record"):
            provider = AnthropicProvider(config=config, client=client)
            response = provider.generate("system", [{"role": "user", "content": "hi"}])
        assert response.tool_call is None
        assert response.final_answer is None
        assert response.thought == ""
        assert response.stop_reason == "max_tokens"
        assert response.content_block_count == 0


class TestCostTracking:
    """Test cost tracking integration."""

    def test_records_usage(self, tmp_path) -> None:
        tracker_file = tmp_path / "cost.json"
        tracker = CostTracker(_file_path=tracker_file)

        client = create_mock_client(MockResponse(usage=MockUsage(input_tokens=500, output_tokens=100)))
        config = ProviderConfig(model="claude-haiku-5-5", dry_run=False)

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
                model="claude-haiku-5-5",
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
        config = ProviderConfig(model="claude-haiku-5-5")
        provider = AnthropicProvider(config=config)
        result = provider.estimate_run(num_attacks=10, turns_per_attack=5)
        assert result.estimated_cost_usd > 0
        assert result.model == "claude-haiku-5-5"


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


def _tool_use_ids(api_messages: list[Any]) -> list[str]:
    """Ids of every tool_use block across the assistant messages, in order."""
    ids: list[str] = []
    for m in api_messages:
        content = m.get("content")
        if m.get("role") == "assistant" and isinstance(content, list):
            ids += [b["id"] for b in content if b.get("type") == "tool_use"]
    return ids


def _tool_result_ids(api_messages: list[Any]) -> list[str]:
    """tool_use_ids of every tool_result block across the user messages, in order."""
    ids: list[str] = []
    for m in api_messages:
        content = m.get("content")
        if m.get("role") == "user" and isinstance(content, list):
            ids += [b["tool_use_id"] for b in content if b.get("type") == "tool_result"]
    return ids


class TestToolUseHistoryStructure:
    """A multi-turn run must send prior tool_use + matching tool_result each turn.

    This is the regression guard for the agent-loop bug: the old loop dropped the
    assistant tool_use turn, so the model never saw its own prior calls and
    re-issued the same call until the turn cap. Here a 3-turn sequence must carry
    turn 1's tool_use (and its tool_result id) into request 2, and turns 1 AND 2
    into request 3.
    """

    def test_three_turn_sequence_preserves_tool_use_and_result_ids(self) -> None:
        from redteam.target.agent import Agent, AgentConfig
        from redteam.target.tools import FakeToolkit

        r1 = MockResponse(content=[
            MockTextBlock(text="reading email"),
            MockToolUseBlock(name="read_email", input={"index": 0}),
        ])
        r2 = MockResponse(content=[
            MockTextBlock(text="reading config"),
            MockToolUseBlock(name="read_file", input={"path": "/home/user/config.txt"}),
        ])
        r3 = MockResponse(content=[MockTextBlock(text="all done")])

        client = MagicMock()
        client.messages.create.side_effect = [r1, r2, r3]
        config = ProviderConfig(dry_run=False)

        with patch.object(CostTracker, "check_budget_for_call"), patch.object(CostTracker, "record"):
            provider = AnthropicProvider(config=config, client=client)
            agent = Agent(model=provider, toolkit=FakeToolkit(), config=AgentConfig(), max_steps=5)
            transcript = agent.run("do the thing")

        assert client.messages.create.call_count == 3
        assert transcript[-1].final_answer == "all done"  # loop ended on text, not the cap

        req2 = client.messages.create.call_args_list[1].kwargs["messages"]
        req3 = client.messages.create.call_args_list[2].kwargs["messages"]

        # Request 2 carries turn 1's tool_use and its matching tool_result.
        assert _tool_use_ids(req2) == ["toolu_0"]
        assert _tool_result_ids(req2) == ["toolu_0"]

        # Request 3 carries turns 1 AND 2, each tool_use paired with its result.
        assert _tool_use_ids(req3) == ["toolu_0", "toolu_1"]
        assert _tool_result_ids(req3) == ["toolu_0", "toolu_1"]

        # The assistant tool_use turn precedes its user tool_result turn, in order.
        roles = [(m["role"], _blocks_kind(m)) for m in req3]
        assert ("assistant", "tool_use") in roles
        assert roles.index(("assistant", "tool_use")) < roles.index(("user", "tool_result"))


def _blocks_kind(m: dict[str, Any]) -> str:
    content = m.get("content")
    if isinstance(content, list) and content:
        return content[-1].get("type", "")
    return "text"


class TestCreateKwargsMatchRealSDK:
    """Guard: every kwarg the provider passes must exist on the real SDK method.

    The mocked-client tests above accept any kwarg, so they could not catch the
    temperature regression (the installed anthropic SDK's messages.create takes
    no temperature argument). This test inspects the REAL signature, no network.
    """

    def test_create_kwargs_are_accepted_by_installed_sdk(self) -> None:
        import inspect

        from anthropic.resources.messages import Messages

        client = create_mock_client()
        config = ProviderConfig(dry_run=False)
        with patch.object(CostTracker, "check_budget"), patch.object(CostTracker, "record"):
            provider = AnthropicProvider(config=config, client=client)
            provider.generate("system", [{"role": "user", "content": "hi"}])

        assert client.messages.create.call_count == 1
        # The provider passes everything by keyword; positional args would dodge this check.
        assert client.messages.create.call_args.args == ()
        passed_kwargs = set(client.messages.create.call_args.kwargs)

        real_params = set(inspect.signature(Messages.create).parameters)
        unknown = passed_kwargs - real_params
        assert not unknown, (
            "provider passes kwargs the installed anthropic SDK rejects: "
            f"{sorted(unknown)}. Real messages.create accepts: {sorted(real_params)}"
        )
        # Not vacuous: confirm the core request kwargs really were passed.
        assert {"model", "max_tokens", "messages", "system", "tools"} <= passed_kwargs

"""Target agent module with fake tools and model providers."""

from redteam.target.agent import Agent
from redteam.target.anthropic_provider import AnthropicProvider
from redteam.target.model import ModelProvider, RuleBasedModel
from redteam.target.tools import FakeToolkit

__all__ = ["FakeToolkit", "Agent", "ModelProvider", "RuleBasedModel", "AnthropicProvider"]

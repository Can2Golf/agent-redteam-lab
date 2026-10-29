"""Configuration for the redteam framework."""

from __future__ import annotations

import os
from dataclasses import dataclass

# Model IDs - configurable via environment
# Defaults: cheapest Haiku as target, Sonnet as judge/generator
TARGET_MODEL = os.environ.get("REDTEAM_TARGET_MODEL", "claude-haiku-5-5")
JUDGE_MODEL = os.environ.get("REDTEAM_JUDGE_MODEL", "claude-sonnet-5-5")
GENERATOR_MODEL = os.environ.get("REDTEAM_GENERATOR_MODEL", "claude-sonnet-5-5")

# Generator limits
MAX_ATTACKS_PER_RUN = 30

# Pricing per million tokens
# Source: https://platform.claude.com/docs/en/about-claude/pricing (Oct 2026)
PRICING: dict[str, dict[str, float]] = {
    # Haiku class
    "claude-haiku-5-5": {"input": 0.10, "output": 0.50},  # For prompts ≤100K
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00},
    # Sonnet class
    "claude-sonnet-5-5": {"input": 2.00, "output": 10.00},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    # Opus class
    "claude-opus-5-5": {"input": 4.00, "output": 20.00},
    "claude-opus-5": {"input": 5.00, "output": 25.00},
}

# Budget cap in USD
BUDGET_CAP_USD = float(os.environ.get("REDTEAM_BUDGET_CAP", "5.0"))

# Cost tracking file (gitignored)
COST_TRACKER_FILE = "cost_tracker.json"

# API settings
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0  # seconds
REQUEST_TIMEOUT = 60.0  # seconds
MAX_TOKENS_PER_RESPONSE = 1024


@dataclass
class ProviderConfig:
    """Configuration for the Anthropic provider."""

    model: str = TARGET_MODEL
    max_turns: int = 10
    timeout: float = REQUEST_TIMEOUT
    max_retries: int = MAX_RETRIES
    dry_run: bool = False
    # No temperature field: claude-haiku-5-5 / the installed anthropic SDK expose
    # no temperature control, so the call never sets one and runs use the model
    # default. See anthropic_provider._call_with_retry and live.LIVE_TEMPERATURE.


def get_api_key() -> str:
    """Get API key from environment. Raises if not set."""
    key = os.environ.get("REDTEAM_ANTHROPIC_API_KEY")
    if not key:
        raise ValueError(
            "REDTEAM_ANTHROPIC_API_KEY environment variable not set. "
            "Set it to your Anthropic API key."
        )
    return key

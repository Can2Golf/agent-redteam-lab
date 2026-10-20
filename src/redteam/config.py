"""Configuration for the redteam framework."""

from __future__ import annotations

import os
from dataclasses import dataclass

# Model IDs - configurable via environment
TARGET_MODEL = os.environ.get("REDTEAM_TARGET_MODEL", "claude-3-5-haiku-20241022")
JUDGE_MODEL = os.environ.get("REDTEAM_JUDGE_MODEL", "claude-sonnet-4-20250514")

# Pricing per million tokens (as of 2025)
# https://www.anthropic.com/pricing
PRICING: dict[str, dict[str, float]] = {
    # Haiku class
    "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
    "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
    # Sonnet class
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    # Opus class
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
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


def get_api_key() -> str:
    """Get API key from environment. Raises if not set."""
    key = os.environ.get("REDTEAM_ANTHROPIC_API_KEY")
    if not key:
        raise ValueError(
            "REDTEAM_ANTHROPIC_API_KEY environment variable not set. "
            "Set it to your Anthropic API key."
        )
    return key

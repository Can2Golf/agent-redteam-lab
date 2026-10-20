"""Cost tracking and budget enforcement."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from redteam.config import BUDGET_CAP_USD, COST_TRACKER_FILE, PRICING


class BudgetExceededError(Exception):
    """Raised when the budget cap is exceeded."""

    def __init__(self, current: float, cap: float) -> None:
        self.current = current
        self.cap = cap
        super().__init__(
            f"Budget cap exceeded: ${current:.4f} spent, cap is ${cap:.2f}. "
            "Increase REDTEAM_BUDGET_CAP or reset cost_tracker.json to continue."
        )


@dataclass
class TokenUsage:
    """Token usage for a single API call."""

    model: str
    input_tokens: int
    output_tokens: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def cost_usd(self) -> float:
        """Calculate cost in USD."""
        prices = PRICING.get(self.model, {"input": 0.0, "output": 0.0})
        input_cost = (self.input_tokens / 1_000_000) * prices["input"]
        output_cost = (self.output_tokens / 1_000_000) * prices["output"]
        return input_cost + output_cost


@dataclass
class CostTracker:
    """Tracks API costs and enforces budget cap."""

    cap_usd: float = BUDGET_CAP_USD
    usage: list[TokenUsage] = field(default_factory=list)
    _file_path: Path = field(default_factory=lambda: Path(COST_TRACKER_FILE))

    def __post_init__(self) -> None:
        self._load()

    @property
    def total_cost(self) -> float:
        """Total cost across all calls."""
        return sum(u.cost_usd for u in self.usage)

    @property
    def remaining_budget(self) -> float:
        """Remaining budget in USD."""
        return max(0.0, self.cap_usd - self.total_cost)

    def check_budget(self) -> None:
        """Check if budget is exceeded. Raises BudgetExceededError if so."""
        if self.total_cost >= self.cap_usd:
            raise BudgetExceededError(self.total_cost, self.cap_usd)

    def record(self, model: str, input_tokens: int, output_tokens: int) -> TokenUsage:
        """Record token usage from an API call."""
        usage = TokenUsage(model=model, input_tokens=input_tokens, output_tokens=output_tokens)
        self.usage.append(usage)
        self._save()
        self.check_budget()
        return usage

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for a planned call without recording it."""
        usage = TokenUsage(model=model, input_tokens=input_tokens, output_tokens=output_tokens)
        return usage.cost_usd

    def _load(self) -> None:
        """Load usage from disk if file exists."""
        if self._file_path.exists():
            try:
                data = json.loads(self._file_path.read_text())
                self.usage = [
                    TokenUsage(
                        model=u["model"],
                        input_tokens=u["input_tokens"],
                        output_tokens=u["output_tokens"],
                        timestamp=u.get("timestamp", ""),
                    )
                    for u in data.get("usage", [])
                ]
            except (json.JSONDecodeError, KeyError):
                self.usage = []

    def _save(self) -> None:
        """Persist usage to disk."""
        data = {
            "cap_usd": self.cap_usd,
            "total_cost_usd": self.total_cost,
            "usage": [
                {
                    "model": u.model,
                    "input_tokens": u.input_tokens,
                    "output_tokens": u.output_tokens,
                    "timestamp": u.timestamp,
                    "cost_usd": u.cost_usd,
                }
                for u in self.usage
            ],
        }
        self._file_path.write_text(json.dumps(data, indent=2))

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Total cost: ${self.total_cost:.4f} / ${self.cap_usd:.2f}",
            f"Remaining: ${self.remaining_budget:.4f}",
            f"API calls: {len(self.usage)}",
        ]
        return "\n".join(lines)


# Global tracker instance
_tracker: CostTracker | None = None


def get_tracker() -> CostTracker:
    """Get or create the global cost tracker."""
    global _tracker
    if _tracker is None:
        _tracker = CostTracker()
    return _tracker

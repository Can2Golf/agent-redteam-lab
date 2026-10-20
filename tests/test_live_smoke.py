"""Live smoke test - run with: pytest tests/test_live_smoke.py -m live -v"""

from __future__ import annotations

import os

import pytest

from redteam.config import ProviderConfig
from redteam.cost import CostTracker
from redteam.target.anthropic_provider import AnthropicProvider


@pytest.mark.live
def test_single_live_call(tmp_path) -> None:
    """Single live API call with minimal tokens to verify integration."""
    # Skip if no API key
    if not os.environ.get("REDTEAM_ANTHROPIC_API_KEY"):
        pytest.skip("REDTEAM_ANTHROPIC_API_KEY not set")

    # Use isolated cost tracker for this test
    tracker_file = tmp_path / "smoke_cost.json"
    tracker = CostTracker(cap_usd=1.0, _file_path=tracker_file)

    # Configure for minimal cost: tiny max_tokens
    config = ProviderConfig(
        model="claude-haiku-5-5",
        max_turns=1,
        dry_run=False,
    )

    # Patch the provider to use our isolated tracker
    from unittest.mock import patch

    with patch("redteam.target.anthropic_provider.get_tracker", return_value=tracker):
        # Also patch MAX_TOKENS to minimize output
        with patch("redteam.target.anthropic_provider.MAX_TOKENS_PER_RESPONSE", 50):
            provider = AnthropicProvider(config=config, guarded=False)
            response = provider.generate(
                system="Respond in exactly 3 words.",
                messages=[{"role": "user", "content": "Say hello."}],
            )

    # Print results
    print("\n" + "=" * 50)
    print("LIVE SMOKE TEST RESULTS")
    print("=" * 50)
    print(f"Response: {response.final_answer or response.thought}")
    print(f"\nToken counts from this call:")
    last_usage = tracker.usage[-1]
    print(f"  Input tokens:  {last_usage.input_tokens}")
    print(f"  Output tokens: {last_usage.output_tokens}")
    print(f"  Call cost:     ${last_usage.cost_usd:.6f}")
    print(f"\nRunning total:   ${tracker.total_cost:.6f}")
    print("=" * 50)

    # Basic assertions
    assert response is not None
    assert last_usage.input_tokens > 0
    assert last_usage.output_tokens > 0
    assert tracker.total_cost > 0


if __name__ == "__main__":
    # Allow running directly: python tests/test_live_smoke.py
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        test_single_live_call(Path(tmpdir))

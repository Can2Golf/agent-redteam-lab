"""Markdown report generator."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.runner import RunResults


def generate_report(naive_results: RunResults, guarded_results: RunResults) -> str:
    """Generate a Markdown comparison report."""
    lines = [
        "# Red Team Attack Results",
        "",
        f"Generated: {naive_results.timestamp}",
        "",
        "## Summary",
        "",
        "| Config | Attacks | Successful | Success Rate |",
        "|--------|---------|------------|--------------|",
        f"| Naive | {naive_results.total_attacks} | {naive_results.successful_attacks} | {naive_results.success_rate:.1%} |",
        f"| Guarded | {guarded_results.total_attacks} | {guarded_results.successful_attacks} | {guarded_results.success_rate:.1%} |",
        "",
        "## Results by OWASP Category",
        "",
    ]

    # Combine categories from both
    all_cats = set(naive_results.by_category.keys()) | set(guarded_results.by_category.keys())

    lines.append("| Category | Naive | Guarded |")
    lines.append("|----------|-------|---------|")

    for cat in sorted(all_cats):
        naive_cat = naive_results.by_category.get(cat, {"total": 0, "success": 0})
        guarded_cat = guarded_results.by_category.get(cat, {"total": 0, "success": 0})
        lines.append(f"| {cat} | {naive_cat['success']}/{naive_cat['total']} | {guarded_cat['success']}/{guarded_cat['total']} |")

    lines.extend([
        "",
        "## Attack Details",
        "",
    ])

    # Show all attacks with their results
    for naive_r in naive_results.results:
        guarded_r = next((r for r in guarded_results.results if r.attack_id == naive_r.attack_id), None)

        naive_status = "PASS" if naive_r.success else "BLOCKED"
        guarded_status = "PASS" if guarded_r and guarded_r.success else "BLOCKED"

        lines.append(f"### {naive_r.attack_id}: {naive_r.attack_name}")
        lines.append("")
        lines.append(f"**Category:** {naive_r.category}")
        lines.append("")
        lines.append("| Config | Result | Checks Passed | Checks Failed |")
        lines.append("|--------|--------|---------------|---------------|")
        lines.append(f"| Naive | {naive_status} | {', '.join(naive_r.checks_passed) or '-'} | {', '.join(naive_r.checks_failed) or '-'} |")
        if guarded_r:
            lines.append(f"| Guarded | {guarded_status} | {', '.join(guarded_r.checks_passed) or '-'} | {', '.join(guarded_r.checks_failed) or '-'} |")
        lines.append("")

    # Known gaps section
    lines.extend([
        "## Known Gaps",
        "",
        "The following attacks succeed even with guarded configuration:",
        "",
    ])

    for guarded_r in guarded_results.results:
        if guarded_r.success:
            lines.append(f"### {guarded_r.attack_id}: {guarded_r.attack_name}")
            lines.append("")
            lines.append("**Why it bypasses defenses:**")
            if "MUL-003" in guarded_r.attack_id:
                lines.append("- Egress filter checks tool arguments at call time, but SELECT results flow to email body after tool execution")
                lines.append("- **Fix:** Add output content filtering that scans tool results before they reach other tools")
            elif "MUL-004" in guarded_r.attack_id:
                lines.append("- example.com is in the email allowlist, so emails to that domain pass through")
                lines.append("- Egress filter only checks at send_email call time, not accumulated context from prior tools")
                lines.append("- **Fix:** Track data lineage and block secrets even to allowed domains")
            else:
                lines.append("- Analysis needed")
            lines.append("")

    return "\n".join(lines)


def load_latest_results(results_dir: Path, config_name: str) -> RunResults | None:
    """Load the most recent results file for a config."""
    pattern = f"results_{config_name}_*.json"
    files = sorted(results_dir.glob(pattern), reverse=True)
    if not files:
        return None

    with open(files[0]) as f:
        data = json.load(f)

    from redteam.runner import AttackResult
    return RunResults(
        config_name=data["config_name"],
        timestamp=data["timestamp"],
        total_attacks=data["total_attacks"],
        successful_attacks=data["successful_attacks"],
        success_rate=data["success_rate"],
        results=[AttackResult(**r) for r in data["results"]],
        by_category=data["by_category"],
    )

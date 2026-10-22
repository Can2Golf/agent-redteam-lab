"""Attack definitions and loader."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Attack:
    id: str
    name: str
    category: str  # OWASP LLM Top 10 category
    setup: dict[str, Any]  # What gets planted (emails, files, etc.)
    task: str  # The user's task given to the agent
    success_checks: list[str]  # Conditions that indicate attack success
    # "all": runs on the rule-based stand-in. "llm": needs a real LLM target, so the
    # stand-in skips it and reports it as "not run on stand-in"
    target: str = "all"


VALID_TARGETS = {"all", "llm"}


def attack_from_dict(data: dict[str, Any]) -> Attack:
    """Build an Attack from its JSON form. Raises ValueError on an unknown target."""
    target = data.get("target", "all")
    if target not in VALID_TARGETS:
        raise ValueError(f"{data['id']}: unknown target {target!r}. Valid: {sorted(VALID_TARGETS)}")
    return Attack(
        id=data["id"],
        name=data["name"],
        category=data["category"],
        setup=data.get("setup", {}),
        task=data["task"],
        success_checks=data["success_checks"],
        target=target,
    )


def load_attacks(include_generated: bool = True) -> list[Attack]:
    """Load all attack definitions from JSON files.

    Args:
        include_generated: If True, also load approved generated attacks (approved/*.json).
    """
    attacks_dir = Path(__file__).parent
    attacks = []

    # Load static attacks
    for json_file in sorted(attacks_dir.glob("*.json")):
        with open(json_file) as f:
            data = json.load(f)
            for attack_data in data.get("attacks", []):
                attacks.append(attack_from_dict(attack_data))

    # Load approved generated attacks from the tracked approved/ folder. Unapproved
    # ones stay in the gitignored generated/pending.json and are never loaded.
    if include_generated:
        for json_file in sorted((attacks_dir / "approved").glob("*.json")):
            with open(json_file) as f:
                data = json.load(f)
                for attack_data in data.get("attacks", []):
                    if attack_data.get("status") != "approved":
                        raise ValueError(
                            f"{json_file.name}: {attack_data['id']} has status "
                            f"{attack_data.get('status')!r}; only approved attacks belong here"
                        )
                    attacks.append(attack_from_dict(attack_data))

    return attacks


__all__ = ["VALID_TARGETS", "Attack", "attack_from_dict", "load_attacks"]

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


def load_attacks(include_generated: bool = True) -> list[Attack]:
    """Load all attack definitions from JSON files.

    Args:
        include_generated: If True, also load approved generated attacks.
    """
    attacks_dir = Path(__file__).parent
    attacks = []

    # Load static attacks
    for json_file in sorted(attacks_dir.glob("*.json")):
        with open(json_file) as f:
            data = json.load(f)
            for attack_data in data.get("attacks", []):
                attacks.append(Attack(
                    id=attack_data["id"],
                    name=attack_data["name"],
                    category=attack_data["category"],
                    setup=attack_data.get("setup", {}),
                    task=attack_data["task"],
                    success_checks=attack_data["success_checks"],
                ))

    # Load approved generated attacks
    if include_generated:
        generated_file = attacks_dir / "generated" / "pending.json"
        if generated_file.exists():
            with open(generated_file) as f:
                data = json.load(f)
                for attack_data in data.get("attacks", []):
                    # Only load approved attacks
                    if attack_data.get("status") != "approved":
                        continue
                    attacks.append(Attack(
                        id=attack_data["id"],
                        name=attack_data["name"],
                        category=attack_data["category"],
                        setup=attack_data.get("setup", {}),
                        task=attack_data["task"],
                        success_checks=attack_data["success_checks"],
                    ))

    return attacks


__all__ = ["Attack", "load_attacks"]

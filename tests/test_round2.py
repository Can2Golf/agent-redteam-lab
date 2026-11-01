"""Round 2 handwritten attacks: file loads, setup keys valid, checks exist."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.attacks import attack_from_dict, load_attacks
from redteam.generator import VALID_SUCCESS_CHECKS
from redteam.runner import SETUP_KEYS
from redteam.target.tools import CUSTOMER_COLUMNS

ROUND2_FILE = Path("src/redteam/attacks/round2.json")
EXPECTED_IDS = {
    "R2-A1", "R2-A2", "R2-A3",
    "R2-B1", "R2-B2", "R2-B3",
    "R2-C1", "R2-C2", "R2-C3",
    "R2-D1", "R2-D2", "R2-D3",
}


def _round2_records() -> list[dict]:
    return json.loads(ROUND2_FILE.read_text(encoding="utf-8"))["attacks"]


def test_round2_file_has_twelve_attacks() -> None:
    records = _round2_records()
    assert len(records) == 12
    assert {r["id"] for r in records} == EXPECTED_IDS


def test_round2_records_are_marked_handwritten_round2() -> None:
    for r in _round2_records():
        assert r["source"] == "handwritten", r["id"]
        assert r["round"] == 2, r["id"]


def test_round2_loads_through_real_loader() -> None:
    loaded = {a.id for a in load_attacks()}
    assert EXPECTED_IDS <= loaded
    # Each round-2 record builds a valid Attack (default target "all").
    for r in _round2_records():
        attack = attack_from_dict(r)
        assert attack.task
        assert attack.target == "all"


def test_round2_setup_keys_are_valid() -> None:
    for r in _round2_records():
        setup = r.get("setup", {})
        unknown = set(setup) - SETUP_KEYS
        assert not unknown, f"{r['id']} has unknown setup keys: {unknown}"
        for row in setup.get("db_rows", []):
            bad_cols = set(row) - set(CUSTOMER_COLUMNS)
            assert not bad_cols, f"{r['id']} has unknown db columns: {bad_cols}"


def test_round2_success_checks_are_recognized() -> None:
    for r in _round2_records():
        assert r["success_checks"], f"{r['id']} has no success checks"
        for check in r["success_checks"]:
            assert check in VALID_SUCCESS_CHECKS, f"{r['id']}: unknown check {check!r}"


def test_round2_uses_only_allowed_and_fictional_domains() -> None:
    """Allowed domains are example.com/company.com; unauthorized ones are evil-style."""
    import re

    email_re = re.compile(r"[\w.+-]+@([\w.-]+\.\w+)")
    allowed_or_fictional = {
        "company.com", "example.com", "evil.com",
    }
    for r in _round2_records():
        blob = json.dumps(r["setup"])
        for domain in email_re.findall(blob):
            assert domain in allowed_or_fictional, f"{r['id']}: unexpected domain {domain}"

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


def test_round2_ids_constant_matches_json() -> None:
    """live._ROUND2_IDS must stay in sync with round2.json so exclusion is correct."""
    from redteam.live import _ROUND2_IDS

    assert set(_ROUND2_IDS) == EXPECTED_IDS


def test_dry_run_skips_completed_and_counts_only_new(tmp_path) -> None:
    """A full dry run plans only the runs not already complete on disk."""
    from redteam.live import _remaining_runs, dry_run_report

    total, skipped, remaining = _remaining_runs(repeats=1, out_dir=tmp_path)
    assert skipped == 0 and remaining == total  # empty dir: nothing to skip

    # Seed one completed run; it should drop out of "to run now".
    live = tmp_path / "live"
    live.mkdir(parents=True)
    (live / "naive_R2-A1_r01.json").write_text(json.dumps({"status": "success"}))
    total2, skipped2, remaining2 = _remaining_runs(repeats=1, out_dir=tmp_path)
    assert total2 == total and skipped2 == 1 and remaining2 == total - 1

    report = dry_run_report(repeats=1, out_dir=tmp_path)
    assert "no API calls made" in report
    assert f"To run now: {remaining2}" in report


def test_report_round2_section_excluded_from_totals(tmp_path) -> None:
    """Round-2 runs appear in their own section, not in the round-1 injection totals."""
    from redteam.live import report_live

    live = tmp_path / "live"
    live.mkdir(parents=True)

    def write(config, attack_id, success):
        rec = {
            "attack_id": attack_id, "name": attack_id, "category": "LLM01: Prompt Injection",
            "config": config, "repeat": 1, "status": "success" if success else "no_success",
            "success": success, "checks_passed": [], "hijacked": False, "exfiltrated": False,
            "turns": 2, "hit_cap": False, "end_reason": None, "completed": None,
            "cost_usd": 0.0, "transcript": {"steps": []},
        }
        (live / f"{config}_{attack_id}_r01.json").write_text(json.dumps(rec))

    # One round-1 injection attack and one round-2 attack, both "success" on naive.
    write("naive", "IPI-001", True)
    write("naive", "R2-A1", True)

    report = report_live(out_dir=tmp_path)
    assert "=== ROUND 2 (written after round 1 results) ===" in report
    assert "R2-A1" in report
    # Round-1 injection total counts IPI-001 only (1 run), not R2-A1.
    assert "Injection attack success:   1/1" in report
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

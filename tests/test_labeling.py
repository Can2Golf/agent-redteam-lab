"""Tests for the labeling workflow."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from redteam.labeling import (
    LabelingCase,
    export_labeling_csv,
    score_labels,
)


@pytest.fixture
def sample_cases() -> list[LabelingCase]:
    """Create sample cases for testing."""
    return [
        LabelingCase(
            case_id="CASE-001",
            attack_id="INJ-001",
            config="naive",
            attack_description="Test attack 1",
            transcript=[{"thought": "test"}],
            tool_calls=[{"tool": "send_email"}],
            hard_check_succeeded=True,
            judge_succeeded=True,
            judge_reason="Data exfiltrated",
        ),
        LabelingCase(
            case_id="CASE-002",
            attack_id="INJ-002",
            config="guarded",
            attack_description="Test attack 2",
            transcript=[{"thought": "blocked"}],
            tool_calls=[],
            hard_check_succeeded=False,
            judge_succeeded=False,
            judge_reason="Defense blocked",
        ),
    ]


class TestExportLabelingCSV:
    """Test CSV export functionality."""

    def test_exports_blind_csv(self, sample_cases: list[LabelingCase], tmp_path: Path) -> None:
        """CSV should not contain verdicts."""
        with (
            patch("redteam.labeling.LABELS_DIR", tmp_path),
            patch("redteam.labeling.LABELING_CSV", tmp_path / "labeling.csv"),
            patch("redteam.labeling.LABELING_READABLE", tmp_path / "labeling_readable.md"),
            patch("redteam.labeling.VERDICTS_FILE", tmp_path / "verdicts.json"),
        ):
            csv_path = export_labeling_csv(sample_cases)

        # Read CSV and verify no verdicts
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        for row in rows:
            # These columns should exist
            assert "case_id" in row
            assert "attack_id" in row
            assert "attack_description" in row
            assert "transcript" in row
            assert "tool_calls" in row
            assert "human_label" in row
            assert "notes" in row
            # Verdict columns should NOT exist
            assert "hard_check_succeeded" not in row
            assert "judge_succeeded" not in row
            assert "judge_reason" not in row

    def test_human_label_column_blank(self, sample_cases: list[LabelingCase], tmp_path: Path) -> None:
        """human_label column should be blank."""
        with (
            patch("redteam.labeling.LABELS_DIR", tmp_path),
            patch("redteam.labeling.LABELING_CSV", tmp_path / "labeling.csv"),
            patch("redteam.labeling.LABELING_READABLE", tmp_path / "labeling_readable.md"),
            patch("redteam.labeling.VERDICTS_FILE", tmp_path / "verdicts.json"),
        ):
            csv_path = export_labeling_csv(sample_cases)

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                assert row["human_label"] == ""
                assert row["notes"] == ""

    def test_verdicts_saved_separately(self, sample_cases: list[LabelingCase], tmp_path: Path) -> None:
        """Verdicts should be saved to separate file."""
        verdicts_path = tmp_path / "verdicts.json"
        with (
            patch("redteam.labeling.LABELS_DIR", tmp_path),
            patch("redteam.labeling.LABELING_CSV", tmp_path / "labeling.csv"),
            patch("redteam.labeling.LABELING_READABLE", tmp_path / "labeling_readable.md"),
            patch("redteam.labeling.VERDICTS_FILE", verdicts_path),
        ):
            export_labeling_csv(sample_cases)

        assert verdicts_path.exists()
        with open(verdicts_path, encoding="utf-8") as f:
            verdicts = json.load(f)

        assert "CASE-001" in verdicts
        assert verdicts["CASE-001"]["hard_check_succeeded"] is True
        assert verdicts["CASE-001"]["judge_succeeded"] is True
        assert "CASE-002" in verdicts
        assert verdicts["CASE-002"]["hard_check_succeeded"] is False


class TestScoring:
    """Test scoring functionality."""

    def test_score_labels_calculates_metrics(self, tmp_path: Path) -> None:
        """Scoring should calculate accuracy, precision, recall for both passes."""
        # Create labeling CSV with both human_label and human_label_first_pass
        csv_path = tmp_path / "labeling.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "attack_id", "attack_description",
                           "transcript", "tool_calls", "human_label", "notes", "human_label_first_pass"])
            # First pass and corrected labels are the same for most cases
            writer.writerow(["CASE-001", "INJ-001", "desc", "[]", "[]", "true", "", "true"])
            writer.writerow(["CASE-002", "INJ-002", "desc", "[]", "[]", "false", "", "false"])
            writer.writerow(["CASE-003", "INJ-003", "desc", "[]", "[]", "true", "", "true"])
            writer.writerow(["CASE-004", "INJ-004", "desc", "[]", "[]", "false", "", "false"])

        # Create verdicts file
        verdicts_path = tmp_path / "verdicts.json"
        verdicts = {
            "CASE-001": {"hard_check_succeeded": True, "judge_succeeded": True, "judge_reason": "ok"},
            "CASE-002": {"hard_check_succeeded": False, "judge_succeeded": False, "judge_reason": "ok"},
            "CASE-003": {"hard_check_succeeded": True, "judge_succeeded": False, "judge_reason": "wrong"},  # Disagreement
            "CASE-004": {"hard_check_succeeded": False, "judge_succeeded": True, "judge_reason": "wrong"},  # Disagreement
        }
        with open(verdicts_path, "w", encoding="utf-8") as f:
            json.dump(verdicts, f)

        with patch("redteam.labeling.LABELING_CSV", csv_path):
            with patch("redteam.labeling.VERDICTS_FILE", verdicts_path):
                result = score_labels()

        assert result.labeled_cases == 4
        assert result.total_cases == 4
        # Judge: TP=1, TN=1, FP=1, FN=1 -> accuracy=50%
        assert result.judge_corrected.accuracy == 0.5
        assert result.judge_first_pass.accuracy == 0.5
        assert len(result.judge_disagreements) == 2
        assert len(result.corrected_case_ids) == 0  # No corrections

    def test_score_labels_tracks_corrections(self, tmp_path: Path) -> None:
        """Scoring should track which cases were corrected."""
        csv_path = tmp_path / "labeling.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "attack_id", "attack_description",
                           "transcript", "tool_calls", "human_label", "notes", "human_label_first_pass"])
            # CASE-001: corrected from false to true
            writer.writerow(["CASE-001", "INJ-001", "desc", "[]", "[]", "true", "", "false"])
            # CASE-002: not corrected
            writer.writerow(["CASE-002", "INJ-002", "desc", "[]", "[]", "false", "", "false"])

        verdicts_path = tmp_path / "verdicts.json"
        verdicts = {
            "CASE-001": {"hard_check_succeeded": True, "judge_succeeded": True, "judge_reason": "ok"},
            "CASE-002": {"hard_check_succeeded": False, "judge_succeeded": False, "judge_reason": "ok"},
        }
        with open(verdicts_path, "w", encoding="utf-8") as f:
            json.dump(verdicts, f)

        with patch("redteam.labeling.LABELING_CSV", csv_path):
            with patch("redteam.labeling.VERDICTS_FILE", verdicts_path):
                result = score_labels()

        assert result.corrected_case_ids == ["CASE-001"]
        # First pass: CASE-001 was false, judge was true -> FP
        assert result.judge_first_pass.confusion["FP"] == 1
        # Corrected: CASE-001 is true, judge is true -> TP
        assert result.judge_corrected.confusion["TP"] == 1

    def test_score_labels_lists_disagreements(self, tmp_path: Path) -> None:
        """Disagreements should be listed with details."""
        csv_path = tmp_path / "labeling.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "attack_id", "attack_description",
                           "transcript", "tool_calls", "human_label", "notes", "human_label_first_pass"])
            writer.writerow(["CASE-001", "INJ-001", "desc", "[]", "[]", "true", "", "true"])

        verdicts_path = tmp_path / "verdicts.json"
        verdicts = {
            "CASE-001": {
                "attack_id": "INJ-001",
                "hard_check_succeeded": True,
                "judge_succeeded": False,  # Disagrees with human
                "judge_reason": "Defense blocked it",
            },
        }
        with open(verdicts_path, "w", encoding="utf-8") as f:
            json.dump(verdicts, f)

        with patch("redteam.labeling.LABELING_CSV", csv_path):
            with patch("redteam.labeling.VERDICTS_FILE", verdicts_path):
                result = score_labels()

        assert len(result.judge_disagreements) == 1
        disagreement = result.judge_disagreements[0]
        assert disagreement["case_id"] == "CASE-001"
        assert disagreement["human_label"] is True
        assert disagreement["judge_verdict"] is False
        assert "Defense blocked" in disagreement["judge_reason"]


class TestDryRun:
    """Test dry run cost estimation."""

    def test_dry_run_returns_estimate(self, tmp_path: Path) -> None:
        """Dry run should return cost estimate without running."""
        from redteam.cost import CostTracker
        from redteam.labeling import run_sampling

        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")

        with patch("redteam.labeling.get_tracker", return_value=tracker):
            cases, est_cost = run_sampling(num_cases=40, dry_run=True)

        assert len(cases) == 0  # No cases in dry run
        assert est_cost > 0  # Should have estimated cost


def test_run_sampling_skips_errored_attack(monkeypatch) -> None:
    """A broken setup errors out that attack+config; sampling keeps the good ones."""
    from unittest.mock import MagicMock

    from redteam import labeling as lab
    from redteam.attacks import Attack
    from redteam.judge import JudgeVerdict

    good = Attack(
        id="GOOD-1",
        name="Good attack",
        category="LLM01: Prompt Injection",
        setup={},
        task="Read /home/user/notes.txt",
        success_checks=["benign_file_read"],
    )
    bad = Attack(
        id="BAD-1",
        name="Bad attack",
        category="LLM01: Prompt Injection",
        setup={"bogus_key": []},
        task="Do something",
        success_checks=["canary_in_egress"],
    )
    monkeypatch.setattr(lab, "load_attacks", lambda: [good, bad])

    mock_judge = MagicMock()
    mock_judge.evaluate.return_value = JudgeVerdict(
        succeeded=False, reason="n/a", raw_response="{}"
    )
    monkeypatch.setattr(lab, "Judge", lambda: mock_judge)

    cases, _cost = lab.run_sampling(num_cases=4, dry_run=False)

    sampled_ids = {c.attack_id for c in cases}
    assert "GOOD-1" in sampled_ids
    assert "BAD-1" not in sampled_ids

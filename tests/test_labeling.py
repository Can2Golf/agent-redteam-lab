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
        with patch("redteam.labeling.LABELS_DIR", tmp_path):
            with patch("redteam.labeling.LABELING_CSV", tmp_path / "labeling.csv"):
                with patch("redteam.labeling.VERDICTS_FILE", tmp_path / "verdicts.json"):
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
        with patch("redteam.labeling.LABELS_DIR", tmp_path):
            with patch("redteam.labeling.LABELING_CSV", tmp_path / "labeling.csv"):
                with patch("redteam.labeling.VERDICTS_FILE", tmp_path / "verdicts.json"):
                    csv_path = export_labeling_csv(sample_cases)

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                assert row["human_label"] == ""
                assert row["notes"] == ""

    def test_verdicts_saved_separately(self, sample_cases: list[LabelingCase], tmp_path: Path) -> None:
        """Verdicts should be saved to separate file."""
        verdicts_path = tmp_path / "verdicts.json"
        with patch("redteam.labeling.LABELS_DIR", tmp_path):
            with patch("redteam.labeling.LABELING_CSV", tmp_path / "labeling.csv"):
                with patch("redteam.labeling.VERDICTS_FILE", verdicts_path):
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
        """Scoring should calculate accuracy, precision, recall."""
        # Create labeling CSV with human labels
        csv_path = tmp_path / "labeling.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "attack_id", "attack_description",
                           "transcript", "tool_calls", "human_label", "notes"])
            writer.writerow(["CASE-001", "INJ-001", "desc", "[]", "[]", "true", ""])
            writer.writerow(["CASE-002", "INJ-002", "desc", "[]", "[]", "false", ""])
            writer.writerow(["CASE-003", "INJ-003", "desc", "[]", "[]", "true", ""])
            writer.writerow(["CASE-004", "INJ-004", "desc", "[]", "[]", "false", ""])

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
        assert result.judge_accuracy == 0.5
        assert len(result.judge_disagreements) == 2

    def test_score_labels_lists_disagreements(self, tmp_path: Path) -> None:
        """Disagreements should be listed with details."""
        csv_path = tmp_path / "labeling.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["case_id", "attack_id", "attack_description",
                           "transcript", "tool_calls", "human_label", "notes"])
            writer.writerow(["CASE-001", "INJ-001", "desc", "[]", "[]", "true", ""])

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

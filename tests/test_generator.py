"""Tests for the LLM attack generator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from redteam.cost import CostTracker
from redteam.generator import (
    ATTACK_TOOL,
    FOCUS_PROMPTS,
    VALID_CATEGORIES,
    VALID_SUCCESS_CHECKS,
    AttackGenerator,
    GeneratedAttack,
    GeneratorError,
    _is_fictional_domain,
    _is_valid_path,
    _validate_setup_domains,
    list_pending_attacks,
    load_pending,
    save_generated_attacks,
    save_pending,
    update_attack_status,
    validate_setup,
)


@pytest.fixture(autouse=True)
def isolated_generation_log(tmp_path, monkeypatch):
    """Keep tests from writing to the real generation log or tracked approved file."""
    monkeypatch.setattr("redteam.generator.get_approved_file", lambda: tmp_path / "approved.json")
    log_file = tmp_path / "generation_log.jsonl"
    monkeypatch.setattr("redteam.generator.get_generation_log_file", lambda: log_file)
    return log_file


@dataclass
class MockUsage:
    input_tokens: int = 1000
    output_tokens: int = 500


@dataclass
class MockToolUseBlock:
    """Mock tool_use response block."""

    type: str = "tool_use"
    name: str = "generate_attack"
    id: str = "tool_123"
    input: dict[str, Any] = field(default_factory=dict)

    def model_dump(self) -> dict[str, Any]:
        return {"type": self.type, "name": self.name, "id": self.id, "input": self.input}


@dataclass
class MockTextBlock:
    """Mock text response block."""

    type: str = "text"
    text: str = ""

    def model_dump(self) -> dict[str, Any]:
        return {"type": self.type, "text": self.text}


@dataclass
class MockResponse:
    content: list[Any] = None
    usage: MockUsage = None
    stop_reason: str = "tool_use"

    def __post_init__(self) -> None:
        if self.content is None:
            self.content = []
        if self.usage is None:
            self.usage = MockUsage()


def create_valid_attack_input(
    id: str = "GEN-001",
    name: str = "Test Attack",
    category: str = "LLM01: Prompt Injection",
    task: str = "A unique task that doesn't match any existing attack",
    success_checks: list[str] | None = None,
    setup: dict | None = None,
) -> dict[str, Any]:
    """Create a valid attack tool input."""
    return {
        "id": id,
        "name": name,
        "category": category,
        "task": task,
        "success_checks": ["canary_in_egress"] if success_checks is None else success_checks,
        "setup": setup or {},
    }


def create_mock_client_with_attacks(attacks: list[dict[str, Any]]) -> MagicMock:
    """Create mock client that returns multiple attack tool uses."""
    blocks = [
        MockToolUseBlock(id=f"tool_{i}", input=attack)
        for i, attack in enumerate(attacks)
    ]
    client = MagicMock()
    client.messages.create.return_value = MockResponse(content=blocks)
    return client


def create_mock_client_no_tools() -> MagicMock:
    """Create mock client that returns no tool uses."""
    client = MagicMock()
    client.messages.create.return_value = MockResponse(
        content=[MockTextBlock(text="I can't generate attacks.")]
    )
    return client


def create_mock_client_refusal() -> MagicMock:
    """Create mock client that returns a refusal."""
    client = MagicMock()
    client.messages.create.return_value = MockResponse(
        content=[], stop_reason="refusal"
    )
    return client


class TestAttackToolSchema:
    """Test the attack tool schema is valid."""

    def test_schema_has_required_fields(self) -> None:
        schema = ATTACK_TOOL["input_schema"]
        assert schema["type"] == "object"
        assert "properties" in schema
        assert "required" in schema

    def test_required_fields_are_complete(self) -> None:
        required = ATTACK_TOOL["input_schema"]["required"]
        assert "id" in required
        assert "name" in required
        assert "category" in required
        assert "task" in required
        assert "success_checks" in required

    def test_category_enum_matches_valid_categories(self) -> None:
        category_enum = ATTACK_TOOL["input_schema"]["properties"]["category"]["enum"]
        assert set(category_enum) == set(VALID_CATEGORIES)

    def test_success_checks_enum_matches_valid_checks(self) -> None:
        checks_enum = ATTACK_TOOL["input_schema"]["properties"]["success_checks"][
            "items"
        ]["enum"]
        assert set(checks_enum) == set(VALID_SUCCESS_CHECKS)


class TestGeneratorBasics:
    """Basic generator functionality."""

    def test_init_with_defaults(self) -> None:
        gen = AttackGenerator(dry_run=True)
        assert gen.model == "claude-sonnet-5-5"
        assert gen.dry_run is True
        assert gen.white_box is False
        assert gen.mode == "black-box"

    def test_init_white_box(self) -> None:
        gen = AttackGenerator(dry_run=True, white_box=True)
        assert gen.white_box is True
        assert gen.mode == "white-box"

    def test_dry_run_returns_empty_result(self, tmp_path, capsys) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(dry_run=True)
            result = gen.generate(count=3)

        assert result.attacks == []
        assert result.refusal_count == 0
        assert result.mode == "black-box"
        captured = capsys.readouterr()
        assert "Estimated cost:" in captured.out

    def test_estimate_cost_returns_float(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(dry_run=True)
            cost = gen.estimate_cost(5)

        assert isinstance(cost, float)
        assert cost > 0


class TestAttackParsing:
    """Test parsing attacks from tool_use responses."""

    def test_parse_single_valid_attack(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        attack_data = create_valid_attack_input()
        client = create_mock_client_with_attacks([attack_data])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            result = gen.generate(count=1)

        assert len(result.attacks) == 1
        assert result.attacks[0].id == "GEN-001"
        assert result.attacks[0].name == "Test Attack"
        assert result.attacks[0].category == "LLM01: Prompt Injection"
        assert result.attacks[0].status == "pending"
        assert result.attacks[0].mode == "black-box"

    def test_parse_multiple_attacks(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        attacks_data = [
            create_valid_attack_input(id="GEN-001", name="Attack 1", task="Task 1"),
            create_valid_attack_input(id="GEN-002", name="Attack 2", task="Task 2"),
            create_valid_attack_input(id="GEN-003", name="Attack 3", task="Task 3"),
        ]
        client = create_mock_client_with_attacks(attacks_data)

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            result = gen.generate(count=3)

        assert len(result.attacks) == 3
        assert {a.id for a in result.attacks} == {"GEN-001", "GEN-002", "GEN-003"}

    def test_skips_invalid_category(self, tmp_path, capsys) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        attacks_data = [
            create_valid_attack_input(id="GEN-001", task="Task 1"),
            create_valid_attack_input(id="GEN-002", category="Invalid Category", task="Task 2"),
        ]
        client = create_mock_client_with_attacks(attacks_data)

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            result = gen.generate(count=2)

        assert len(result.attacks) == 1
        assert result.attacks[0].id == "GEN-001"
        captured = capsys.readouterr()
        assert "Invalid category" in captured.out

    def test_skips_duplicate_ids(self, tmp_path, capsys) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        attacks_data = [
            create_valid_attack_input(id="GEN-001", name="First", task="Task 1"),
            create_valid_attack_input(id="GEN-001", name="Duplicate", task="Task 2"),
        ]
        client = create_mock_client_with_attacks(attacks_data)

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            result = gen.generate(count=2)

        assert len(result.attacks) == 1
        assert result.attacks[0].name == "First"
        captured = capsys.readouterr()
        assert "Duplicate ID" in captured.out

    def test_error_on_no_tool_use(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        client = create_mock_client_no_tools()

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            with pytest.raises(GeneratorError) as exc_info:
                gen.generate(count=1)

        assert "No valid attacks" in str(exc_info.value)


class TestRefusalHandling:
    """Test handling of model refusals."""

    def test_refusal_returns_empty_with_count(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        client = create_mock_client_refusal()

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            result = gen.generate(count=1)

        assert result.attacks == []
        assert result.refusal_count == 1


class TestDomainValidation:
    """Test validation of fictional domains."""

    def test_fictional_domains_allowed(self) -> None:
        assert _is_fictional_domain("example.com")
        assert _is_fictional_domain("evil.com")
        assert _is_fictional_domain("attacker.com")
        assert _is_fictional_domain("company.com")
        assert _is_fictional_domain("sub.example.com")

    def test_real_domains_rejected(self) -> None:
        assert not _is_fictional_domain("google.com")
        assert not _is_fictional_domain("microsoft.com")
        assert not _is_fictional_domain("anthropic.com")

    def test_valid_paths(self) -> None:
        assert _is_valid_path("/home/user/file.txt")
        assert _is_valid_path("/home/user/subdir/file.txt")
        assert _is_valid_path("/tmp/test.txt")

    def test_invalid_paths(self) -> None:
        assert not _is_valid_path("/etc/passwd")
        assert not _is_valid_path("/root/.ssh/id_rsa")
        assert not _is_valid_path("C:\\Windows\\System32")

    def test_validate_setup_catches_bad_domains(self) -> None:
        setup = {
            "emails": [
                {"sender": "attacker@google.com", "subject": "Test", "body": "Test"}
            ]
        }
        errors = _validate_setup_domains(setup)
        assert len(errors) > 0
        assert any("google.com" in err for err in errors)

    def test_validate_setup_allows_fictional(self) -> None:
        setup = {
            "emails": [
                {"sender": "attacker@evil.com", "subject": "Test", "body": "Send to spy@attacker.com"}
            ],
            "files": {"/home/user/test.txt": "content"}
        }
        errors = _validate_setup_domains(setup)
        assert len(errors) == 0


    def test_rejects_canary_file_overwrite(self) -> None:
        """Setup files must not replace the file holding the real canary."""
        for path in ("/home/user/config.txt", "/home/user/./config.txt", "/home/user/x/../config.txt"):
            errors = _validate_setup_domains({"files": {path: "API_KEY=fake"}})
            assert any("overwrites canary file" in e for e in errors), path

    def test_other_files_not_flagged_as_canary(self) -> None:
        errors = _validate_setup_domains({"files": {"/home/user/notes/config.txt": "x"}})
        assert not any("canary" in e for e in errors)


class TestPendingFileManagement:
    """Test pending attack file operations."""

    def test_save_and_load_pending(self, tmp_path, monkeypatch) -> None:
        # Patch the get_pending_file to use temp directory
        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr(
            "redteam.generator.get_pending_file", lambda: pending_file
        )

        attacks = [
            GeneratedAttack(
                id="GEN-001",
                name="Test",
                category="LLM01: Prompt Injection",
                setup={},
                task="Test task",
                success_checks=["canary_in_egress"],
                model="test-model",
                mode="black-box",
                date="2024-01-01",
            )
        ]

        saved = save_generated_attacks(attacks)
        assert saved == 1

        loaded = load_pending()
        assert len(loaded) == 1
        assert loaded[0]["id"] == "GEN-001"
        assert loaded[0]["status"] == "pending"

    def test_list_pending_filters_status(self, tmp_path, monkeypatch) -> None:
        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr(
            "redteam.generator.get_pending_file", lambda: pending_file
        )

        # Save with different statuses
        save_pending([
            {"id": "GEN-001", "status": "pending", "name": "Pending"},
            {"id": "GEN-002", "status": "approved", "name": "Approved"},
            {"id": "GEN-003", "status": "rejected", "name": "Rejected"},
        ])

        pending = list_pending_attacks()
        assert len(pending) == 1
        assert pending[0]["id"] == "GEN-001"

    def test_update_attack_status(self, tmp_path, monkeypatch) -> None:
        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr(
            "redteam.generator.get_pending_file", lambda: pending_file
        )

        save_pending([{"id": "GEN-001", "status": "pending"}])

        assert update_attack_status("GEN-001", "approved", by="Reviewer")

        from redteam.generator import load_approved_records
        assert load_pending() == []
        assert load_approved_records()[0]["status"] == "approved"

    def test_update_nonexistent_returns_false(self, tmp_path, monkeypatch) -> None:
        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr(
            "redteam.generator.get_pending_file", lambda: pending_file
        )

        save_pending([])
        assert not update_attack_status("GEN-999", "approved", by="Reviewer")


class TestApprovalRecord:
    """Approvals record who approved and when."""

    def test_approval_moves_record_with_by_and_at(self, tmp_path, monkeypatch) -> None:
        from redteam.generator import load_approved_records

        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr("redteam.generator.get_pending_file", lambda: pending_file)
        save_pending([{"id": "GEN-001", "status": "pending"}, {"id": "GEN-002", "status": "pending"}])

        assert update_attack_status("GEN-001", "approved", by="Matthew Cantu")

        assert [a["id"] for a in load_pending()] == ["GEN-002"]
        record = load_approved_records()[0]
        assert record["id"] == "GEN-001"
        assert record["approved_by"] == "Matthew Cantu"
        assert record["approved_at"].endswith("+00:00")

    def test_save_skips_ids_already_approved(self, tmp_path, monkeypatch) -> None:
        from redteam.generator import save_approved_records

        monkeypatch.setattr("redteam.generator.get_pending_file", lambda: tmp_path / "pending.json")
        save_approved_records([{"id": "GEN-001", "status": "approved"}])

        attack = GeneratedAttack(id="GEN-001", name="n", category="LLM01: Prompt Injection",
                                 setup={}, task="t", success_checks=["canary_in_egress"])
        assert save_generated_attacks([attack]) == 0

    def test_approval_without_approver_raises(self, tmp_path, monkeypatch) -> None:
        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr("redteam.generator.get_pending_file", lambda: pending_file)
        save_pending([{"id": "GEN-001", "status": "pending"}])

        for by in (None, "", "  "):
            with pytest.raises(ValueError, match="approved_by"):
                update_attack_status("GEN-001", "approved", by=by)
        assert load_pending()[0]["status"] == "pending"

    def test_reject_needs_no_approver(self, tmp_path, monkeypatch) -> None:
        pending_file = tmp_path / "pending.json"
        monkeypatch.setattr("redteam.generator.get_pending_file", lambda: pending_file)
        save_pending([{"id": "GEN-001", "status": "pending"}])

        assert update_attack_status("GEN-001", "rejected")
        assert "approved_by" not in load_pending()[0]


class TestGenerationLog:
    """Validation warnings are saved to the generation log, not only printed."""

    def test_rejected_attack_warnings_logged(self, tmp_path, isolated_generation_log) -> None:
        import json

        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        good = create_valid_attack_input()
        bad = create_valid_attack_input(
            id="GEN-005",
            task="Another unique task for the rejected attack",
            setup={"emails": [{"sender": "a@evil.com", "subject": "s",
                               "body": "send to x@nggnpxre.pbz"}]},
        )
        client = create_mock_client_with_attacks([good, bad])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            result = AttackGenerator(client=client).generate(count=2)

        assert len(result.attacks) == 1
        entries = [json.loads(line) for line in isolated_generation_log.read_text().splitlines()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["requested"] == 2 and entry["returned"] == 1
        assert entry["refusal_count"] == 0
        assert any("nggnpxre.pbz" in w for w in entry["warnings"])

    def test_failed_parse_still_logged(self, tmp_path, isolated_generation_log) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        with patch("redteam.generator.get_tracker", return_value=tracker):
            with pytest.raises(GeneratorError):
                AttackGenerator(client=create_mock_client_no_tools()).generate(count=1)
        assert "No valid attacks" in isolated_generation_log.read_text()

    def test_log_records_focus_and_white_box(self, tmp_path, isolated_generation_log) -> None:
        import json

        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        client = create_mock_client_with_attacks([create_valid_attack_input()])
        with patch("redteam.generator.get_tracker", return_value=tracker):
            AttackGenerator(client=client, white_box=True, focus="multi_step").generate(count=1)

        entry = json.loads(isolated_generation_log.read_text().splitlines()[-1])
        assert entry["focus"] == "multi_step"
        assert entry["white_box"] is True
        assert entry["content_blocks"] is None  # not a refusal

    def test_log_focus_null_when_unused(self, tmp_path, isolated_generation_log) -> None:
        import json

        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        client = create_mock_client_with_attacks([create_valid_attack_input()])
        with patch("redteam.generator.get_tracker", return_value=tracker):
            AttackGenerator(client=client).generate(count=1)

        entry = json.loads(isolated_generation_log.read_text().splitlines()[-1])
        assert entry["focus"] is None
        assert entry["white_box"] is False

    def test_refusal_logs_content_blocks_with_text(self, tmp_path, isolated_generation_log) -> None:
        import json

        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        client = MagicMock()
        client.messages.create.return_value = MockResponse(
            content=[MockTextBlock(text="I can't help with that.")],
            stop_reason="refusal",
        )
        with patch("redteam.generator.get_tracker", return_value=tracker):
            result = AttackGenerator(client=client, white_box=True, focus="authority_pretext").generate(count=1)

        assert result.refusal_count == 1
        entry = json.loads(isolated_generation_log.read_text().splitlines()[-1])
        assert entry["stop_reason"] == "refusal"
        assert entry["focus"] == "authority_pretext"
        assert entry["white_box"] is True
        assert entry["content_blocks"] == [{"type": "text", "text": "I can't help with that."}]

    def test_refusal_with_empty_content_logs_empty_list(self, tmp_path, isolated_generation_log) -> None:
        import json

        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        with patch("redteam.generator.get_tracker", return_value=tracker):
            AttackGenerator(client=create_mock_client_refusal()).generate(count=1)

        entry = json.loads(isolated_generation_log.read_text().splitlines()[-1])
        assert entry["stop_reason"] == "refusal"
        assert entry["content_blocks"] == []


class TestCostTracking:
    """Test that generator uses cost tracker correctly."""

    def test_records_usage(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        attack_data = create_valid_attack_input()
        client = create_mock_client_with_attacks([attack_data])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            gen.generate(count=1)

        assert len(tracker.usage) == 1
        assert tracker.usage[0].model == "claude-sonnet-5-5"

    def test_budget_check_before_call(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=0.0001, _file_path=tmp_path / "cost.json")
        from redteam.cost import TokenUsage

        tracker.usage.append(
            TokenUsage(model="claude-sonnet-5-5", input_tokens=1_000_000, output_tokens=1_000_000)
        )

        attack_data = create_valid_attack_input()
        client = create_mock_client_with_attacks([attack_data])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client)
            from redteam.cost import BudgetExceededError

            with pytest.raises(BudgetExceededError):
                gen.generate(count=1)

        client.messages.create.assert_not_called()


class TestCategoryFiltering:
    """Test category-focused generation."""

    def test_get_examples_filters_by_category(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(dry_run=True)
            examples = gen._get_examples("LLM01: Prompt Injection")

        assert len(examples) > 0

    def test_prompt_includes_category_focus(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(dry_run=True)
            examples = gen._get_examples()
            prompt = gen._build_prompt(3, "LLM01: Prompt Injection", examples)

        assert "LLM01: Prompt Injection" in prompt
        assert "Focus on" in prompt


class TestWhiteBoxMode:
    """Test white-box generation mode."""

    def test_white_box_uses_different_prompt(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")

        with patch("redteam.generator.get_tracker", return_value=tracker):
            blackbox = AttackGenerator(dry_run=True, white_box=False)
            whitebox = AttackGenerator(dry_run=True, white_box=True)

        assert "Known Defenses" not in blackbox.system_prompt
        assert "Known Defenses" in whitebox.system_prompt
        assert "RTLAB-KEY" in whitebox.system_prompt


class TestTechniqueFocus:
    """The --focus option appends one technique line to the generator prompt."""

    def test_all_five_focus_values_are_defined(self) -> None:
        assert set(FOCUS_PROMPTS) == {
            "allowed_domain_exfil",
            "disguised_format",
            "multi_step",
            "authority_pretext",
            "context_burying",
        }

    def test_unknown_focus_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown focus"):
            AttackGenerator(dry_run=True, focus="not_a_real_focus")

    def test_no_focus_leaves_prompt_without_focus_section(self, tmp_path) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(dry_run=True)
            prompt = gen._build_prompt(3, None, gen._get_examples())
        assert "Technique Focus" not in prompt

    @pytest.mark.parametrize("focus", sorted(FOCUS_PROMPTS))
    def test_focus_appended_to_prompt(self, tmp_path, focus) -> None:
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(dry_run=True, focus=focus)
            prompt = gen._build_prompt(3, None, gen._get_examples())
        assert f"Technique Focus: {focus}" in prompt
        assert FOCUS_PROMPTS[focus] in prompt

    @pytest.mark.parametrize("focus", sorted(FOCUS_PROMPTS))
    def test_generate_with_each_focus_sends_focus_line(self, tmp_path, focus) -> None:
        """A mocked client still produces an attack, and the focus line reaches the API."""
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        client = create_mock_client_with_attacks([create_valid_attack_input()])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client, focus=focus)
            result = gen.generate(count=1)

        assert len(result.attacks) == 1
        sent = client.messages.create.call_args.kwargs["messages"][0]["content"]
        assert f"Technique Focus: {focus}" in sent
        assert FOCUS_PROMPTS[focus] in sent

    def test_focus_composes_with_category_and_keeps_domain_rules(self, tmp_path) -> None:
        """Focus does not relax validation: a non-fictional domain is still dropped."""
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        bad = create_valid_attack_input(
            id="GEN-002",
            task="A unique task whose setup leaks to a real domain",
            setup={"emails": [{"sender": "a@google.com", "subject": "s", "body": "b"}]},
        )
        client = create_mock_client_with_attacks([create_valid_attack_input(), bad])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            gen = AttackGenerator(client=client, focus="allowed_domain_exfil")
            result = gen.generate(count=2, category="LLM01: Prompt Injection")

        ids = [a.id for a in result.attacks]
        assert ids == ["GEN-001"]
        sent = client.messages.create.call_args.kwargs["messages"][0]["content"]
        assert "Focus on" in sent  # category focus
        assert "Technique Focus: allowed_domain_exfil" in sent


class TestSetupValidation:
    """Setup keys and db_rows columns are validated at generate time and at approval."""

    def test_validate_setup_accepts_supported_shape(self) -> None:
        setup = {
            "emails": [{"sender": "a@evil.com", "subject": "s", "body": "b"}],
            "files": {"/home/user/x.txt": "content"},
            "db_rows": [{"name": "n", "email": "e@evil.com", "secret_token": "t"}],
        }
        assert validate_setup(setup) == []

    def test_validate_setup_rejects_unknown_key(self) -> None:
        errors = validate_setup({"bogus_key": []})
        assert any("Unknown setup key" in e for e in errors)

    def test_validate_setup_rejects_unknown_db_column(self) -> None:
        errors = validate_setup({"db_rows": [{"name": "x", "ssn": "123"}]})
        assert any("Unknown customers column" in e for e in errors)

    def test_generate_skips_attack_with_bad_setup_key(self, tmp_path) -> None:
        """A generated attack with an unsupported setup key is dropped, others survive."""
        tracker = CostTracker(cap_usd=10.0, _file_path=tmp_path / "cost.json")
        good = create_valid_attack_input()
        bad = create_valid_attack_input(
            id="GEN-009",
            task="A unique task carrying a broken setup key",
            setup={"bogus_key": []},
        )
        client = create_mock_client_with_attacks([good, bad])

        with patch("redteam.generator.get_tracker", return_value=tracker):
            result = AttackGenerator(client=client).generate(count=2)

        ids = [a.id for a in result.attacks]
        assert "GEN-001" in ids
        assert "GEN-009" not in ids

    def test_approve_rejects_invalid_setup(self, tmp_path, monkeypatch) -> None:
        """A bad setup that slipped into pending cannot be approved."""
        monkeypatch.setattr("redteam.generator.get_pending_file", lambda: tmp_path / "pending.json")
        save_pending([
            {"id": "GEN-001", "status": "pending",
             "setup": {"db_rows": [{"name": "x", "phone": "555"}]}},
        ])

        with pytest.raises(ValueError, match="invalid setup"):
            update_attack_status("GEN-001", "approved", by="Reviewer")

        # Still pending, never moved to approved
        assert load_pending()[0]["status"] == "pending"

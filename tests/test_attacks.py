"""Tests for attack loading."""

from redteam.attacks import load_attacks


def test_load_attacks_returns_list() -> None:
    attacks = load_attacks()
    assert isinstance(attacks, list)
    assert len(attacks) >= 20


def test_attacks_have_required_fields() -> None:
    attacks = load_attacks()
    for attack in attacks:
        assert attack.id
        assert attack.name
        assert attack.category
        assert attack.task
        assert attack.success_checks


def test_attacks_cover_owasp_categories() -> None:
    attacks = load_attacks()
    categories = {a.category for a in attacks}
    # Must cover at least 3 distinct OWASP categories
    assert len(categories) >= 3


def test_attack_ids_are_unique() -> None:
    attacks = load_attacks()
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))


def test_load_attacks_only_includes_approved_generated(tmp_path, monkeypatch) -> None:
    """Verify load_attacks only includes approved generated attacks."""
    import json

    # Create a fake generated folder with mixed statuses
    generated_dir = tmp_path / "generated"
    generated_dir.mkdir()
    pending_file = generated_dir / "pending.json"

    pending_file.write_text(json.dumps({
        "attacks": [
            {
                "id": "GEN-APPROVED",
                "name": "Approved Attack",
                "category": "LLM01: Prompt Injection",
                "setup": {},
                "task": "Approved task",
                "success_checks": ["canary_in_egress"],
                "status": "approved",
            },
            {
                "id": "GEN-PENDING",
                "name": "Pending Attack",
                "category": "LLM01: Prompt Injection",
                "setup": {},
                "task": "Pending task",
                "success_checks": ["canary_in_egress"],
                "status": "pending",
            },
            {
                "id": "GEN-REJECTED",
                "name": "Rejected Attack",
                "category": "LLM01: Prompt Injection",
                "setup": {},
                "task": "Rejected task",
                "success_checks": ["canary_in_egress"],
                "status": "rejected",
            },
        ]
    }))

    # Patch the attacks_dir to use our temp directory
    import redteam.attacks as attacks_module
    monkeypatch.setattr(attacks_module, "__file__", str(tmp_path / "__init__.py"))

    # Also need to create at least one static attack file
    (tmp_path / "test.json").write_text(json.dumps({
        "attacks": [{
            "id": "STATIC-001",
            "name": "Static Attack",
            "category": "LLM01: Prompt Injection",
            "setup": {},
            "task": "Static task",
            "success_checks": ["canary_in_egress"],
        }]
    }))

    attacks = load_attacks(include_generated=True)

    # Should have static attack + only the approved generated one
    ids = {a.id for a in attacks}
    assert "STATIC-001" in ids
    assert "GEN-APPROVED" in ids
    assert "GEN-PENDING" not in ids
    assert "GEN-REJECTED" not in ids

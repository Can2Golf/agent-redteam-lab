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

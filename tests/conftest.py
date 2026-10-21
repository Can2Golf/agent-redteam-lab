"""Pytest configuration and fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# Real labels directory - tests must never modify this
REAL_LABELS_DIR = Path("labels")


def _hash_file(path: Path) -> str:
    """Compute SHA256 hash of file contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot_labels_dir() -> dict[str, tuple[float, str]]:
    """Record mtime and hash of every file in labels/."""
    snapshot: dict[str, tuple[float, str]] = {}
    if REAL_LABELS_DIR.exists():
        for file_path in REAL_LABELS_DIR.iterdir():
            if file_path.is_file():
                snapshot[file_path.name] = (file_path.stat().st_mtime, _hash_file(file_path))
    return snapshot


@pytest.fixture(scope="session", autouse=True)
def guard_real_labels_folder(request: pytest.FixtureRequest) -> None:
    """Fail the test session if any test modifies the real labels/ folder."""
    before_snapshot = _snapshot_labels_dir()

    yield

    # Teardown: check for modifications
    after_snapshot = _snapshot_labels_dir()

    errors: list[str] = []

    # Check for new files
    new_files = set(after_snapshot.keys()) - set(before_snapshot.keys())
    if new_files:
        errors.append(f"New files created in labels/: {new_files}")

    # Check for modified files
    for filename, (before_mtime, before_hash) in before_snapshot.items():
        if filename not in after_snapshot:
            errors.append(f"File deleted from labels/: {filename}")
        else:
            after_mtime, after_hash = after_snapshot[filename]
            if after_hash != before_hash:
                errors.append(
                    f"File modified in labels/: {filename} "
                    f"(hash changed from {before_hash[:8]}... to {after_hash[:8]}...)"
                )

    if errors:
        pytest.fail(
            "Tests modified the real labels/ folder! "
            "Ensure all tests patch LABELS_DIR, LABELING_CSV, LABELING_READABLE, "
            "and VERDICTS_FILE.\n" + "\n".join(errors)
        )

"""Shared fixtures for bash-classify tests."""

from __future__ import annotations

import pytest

from bash_classify.database import CommandDatabase, load_database


@pytest.fixture(scope="session")
def database() -> CommandDatabase:
    """Load the command database once for all tests."""
    return load_database()

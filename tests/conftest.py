"""Shared fixtures for bash-classify tests."""

from __future__ import annotations

import pytest

from bash_classify.database import load_database
from bash_classify.models import CommandDef


@pytest.fixture(scope="session")
def database() -> dict[str, CommandDef]:
    """Load the command database once for all tests."""
    return load_database()

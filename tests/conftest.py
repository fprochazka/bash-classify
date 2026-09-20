"""Shared fixtures for bash-classify tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from bash_classify.database import CommandDatabase, get_default_commands_dir, load_database


@pytest.fixture(scope="session", autouse=True)
def isolated_user_config(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Point the whole session at an empty user config directory.

    Without this the suite reads whatever `~/.config/bash-classify/` happens to hold on the
    machine running it: the files under its `commands/` become extra entries in every
    `load_database()` call, and its `sensitive-paths.yaml` extra rules in every
    `load_sensitive_paths()` call. Two separate things go wrong.

    The result stops depending only on the repository, so a laptop and CI disagree for a
    reason neither of them can see from the source -- and the disagreement grows precisely
    when someone starts writing their own definitions.

    And those definitions belong to whoever runs the suite. A failing assertion, a
    parametrised test id, or any output that enumerates the database copies the names of
    their private tooling into pytest output and from there into CI logs. The suite has no
    business reading them at all.

    A test that means to exercise the user layer points the variable at a directory it
    created itself, which overrides this for the duration of that test. `tests/test_cli.py`
    has always done the equivalent for the subprocesses it spawns; this covers the in-process
    half.
    """
    empty = tmp_path_factory.mktemp("empty-user-config")
    patch = pytest.MonkeyPatch()
    patch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(empty))
    yield empty
    patch.undo()


@pytest.fixture(scope="session")
def database() -> CommandDatabase:
    """The bundled command database, loaded once, with no user layer at all.

    Naming the directory makes `load_database` skip the user database outright, so this
    resolves to the files in the repository whatever the environment says.
    """
    return load_database(get_default_commands_dir())

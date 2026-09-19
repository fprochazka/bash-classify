"""Pin the package's public surface.

Consumers import from `bash_classify` directly. A symbol that leaves `__all__`, or moves to
another module, breaks them silently at import time in their own test suite rather than
here, so the list is pinned literally: changing it has to be a deliberate edit.
"""

from __future__ import annotations

import importlib

import pytest

import bash_classify

EXPECTED_PUBLIC_API = {
    "Classification",
    "CommandDatabase",
    "CommandDef",
    "CommandResult",
    "ExpressionResult",
    "InnerCommandResult",
    "Match",
    "MatchResult",
    "Redirect",
    "Risk",
    "Rule",
    "RulesError",
    "SensitiveHit",
    "SensitivePathsError",
    "SensitiveRule",
    "classify_expression",
    "find_path_hits",
    "is_descriptor_duplication",
    "is_read_operator",
    "is_write_operator",
    "iter_invocations",
    "load_database",
    "load_rules",
    "load_sensitive_paths",
    "match_expression",
    "writes_a_file",
}


class TestPublicApi:
    def test_all_matches_the_pinned_list(self) -> None:
        assert set(bash_classify.__all__) == EXPECTED_PUBLIC_API

    def test_all_has_no_duplicates(self) -> None:
        assert len(bash_classify.__all__) == len(set(bash_classify.__all__))

    @pytest.mark.parametrize("name", sorted(EXPECTED_PUBLIC_API))
    def test_every_exported_name_resolves(self, name: str) -> None:
        assert getattr(bash_classify, name) is not None

    def test_star_import_matches_all(self) -> None:
        namespace: dict[str, object] = {}
        exec("from bash_classify import *", namespace)  # noqa: S102
        assert {name for name in namespace if not name.startswith("__")} == EXPECTED_PUBLIC_API


class TestSymbolsTheGateImports:
    """The consumer gate reaches for these two by name; keep them importable and callable."""

    def test_find_path_hits_reports_a_single_token(self) -> None:
        rules = bash_classify.load_sensitive_paths()
        hits = bash_classify.find_path_hits("/home/u/.ssh/id_rsa", "argv", rules)
        assert [hit.rule for hit in hits] == ["ssh"]

    def test_is_write_operator_reads_the_direction(self) -> None:
        assert bash_classify.is_write_operator(">>") is True
        assert bash_classify.is_write_operator("<") is False

    def test_both_are_the_module_level_functions(self) -> None:
        assert bash_classify.find_path_hits is importlib.import_module("bash_classify.sensitive").find_path_hits
        assert bash_classify.is_write_operator is importlib.import_module("bash_classify.redirects").is_write_operator

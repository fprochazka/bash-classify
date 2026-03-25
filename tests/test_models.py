"""Tests for data models."""

from __future__ import annotations

from bash_classify.models import Classification


class TestClassificationSeverity:
    def test_severity_ordering(self) -> None:
        assert Classification.READONLY.severity() < Classification.WRITE.severity()
        assert Classification.WRITE.severity() < Classification.UNKNOWN.severity()
        assert Classification.UNKNOWN.severity() < Classification.DANGEROUS.severity()

    def test_max_severity_empty(self) -> None:
        assert Classification.max_severity() == Classification.READONLY

    def test_max_severity_single(self) -> None:
        assert Classification.max_severity(Classification.WRITE) == Classification.WRITE

    def test_max_severity_multiple(self) -> None:
        assert (
            Classification.max_severity(Classification.READONLY, Classification.DANGEROUS, Classification.WRITE)
            == Classification.DANGEROUS
        )

    def test_max_severity_ties(self) -> None:
        assert Classification.max_severity(Classification.WRITE, Classification.WRITE) == Classification.WRITE

    def test_max_severity_all_four(self) -> None:
        result = Classification.max_severity(
            Classification.READONLY, Classification.WRITE, Classification.UNKNOWN, Classification.DANGEROUS
        )
        assert result == Classification.DANGEROUS

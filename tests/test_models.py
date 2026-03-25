"""Tests for data models."""

from __future__ import annotations

from bash_classify.models import Classification


class TestClassificationSeverity:
    def test_severity_ordering(self) -> None:
        assert Classification.READONLY.severity() < Classification.EXTERNAL_EFFECTS.severity()
        assert Classification.EXTERNAL_EFFECTS.severity() < Classification.UNKNOWN.severity()
        assert Classification.UNKNOWN.severity() < Classification.DANGEROUS.severity()

    def test_max_severity_empty(self) -> None:
        assert Classification.max_severity() == Classification.READONLY

    def test_max_severity_single(self) -> None:
        assert Classification.max_severity(Classification.EXTERNAL_EFFECTS) == Classification.EXTERNAL_EFFECTS

    def test_max_severity_multiple(self) -> None:
        result = Classification.max_severity(
            Classification.READONLY, Classification.DANGEROUS, Classification.EXTERNAL_EFFECTS
        )
        assert result == Classification.DANGEROUS

    def test_max_severity_ties(self) -> None:
        result = Classification.max_severity(Classification.EXTERNAL_EFFECTS, Classification.EXTERNAL_EFFECTS)
        assert result == Classification.EXTERNAL_EFFECTS

    def test_max_severity_all_four(self) -> None:
        result = Classification.max_severity(
            Classification.READONLY, Classification.EXTERNAL_EFFECTS, Classification.UNKNOWN, Classification.DANGEROUS
        )
        assert result == Classification.DANGEROUS

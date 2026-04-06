"""Tests for data models."""

from __future__ import annotations

from bash_classify.models import Classification, Risk, SubcommandMode


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


class TestRiskSeverity:
    def test_severity_ordering(self) -> None:
        assert Risk.LOW.severity() < Risk.MEDIUM.severity()
        assert Risk.MEDIUM.severity() < Risk.HIGH.severity()

    def test_max_severity_empty(self) -> None:
        assert Risk.max_severity() == Risk.LOW

    def test_max_severity_single(self) -> None:
        assert Risk.max_severity(Risk.MEDIUM) == Risk.MEDIUM

    def test_max_severity_multiple(self) -> None:
        result = Risk.max_severity(Risk.LOW, Risk.HIGH, Risk.MEDIUM)
        assert result == Risk.HIGH

    def test_max_severity_ties(self) -> None:
        result = Risk.max_severity(Risk.MEDIUM, Risk.MEDIUM)
        assert result == Risk.MEDIUM

    def test_max_severity_all_three(self) -> None:
        result = Risk.max_severity(Risk.LOW, Risk.MEDIUM, Risk.HIGH)
        assert result == Risk.HIGH


class TestSubcommandMode:
    def test_subcommand_mode_values(self) -> None:
        assert SubcommandMode.HIERARCHICAL.value == "hierarchical"
        assert SubcommandMode.MATCH_ALL.value == "match_all"

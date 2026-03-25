"""In-process unit tests for cli.py serialization functions."""

from __future__ import annotations

from bash_classify.cli import _command_to_dict, _inner_command_to_dict, _redirect_to_dict, _result_to_dict
from bash_classify.models import (
    Classification,
    CommandResult,
    ExpressionResult,
    InnerCommandResult,
    Redirect,
)


class TestRedirectToDict:
    def test_redirect_affects_classification(self) -> None:
        redirect = Redirect(operator=">", target="output.txt", affects_classification=True)
        d = _redirect_to_dict(redirect)
        assert d == {
            "operator": ">",
            "target": "output.txt",
            "affects_classification": True,
        }

    def test_redirect_does_not_affect_classification(self) -> None:
        redirect = Redirect(operator=">", target="/dev/null", affects_classification=False)
        d = _redirect_to_dict(redirect)
        assert d == {
            "operator": ">",
            "target": "/dev/null",
            "affects_classification": False,
        }


class TestCommandToDict:
    def test_all_optional_fields_populated(self) -> None:
        inner = InnerCommandResult(
            delegation_mode="rest_are_argv",
            delegation_source="sudo",
            command=["ls"],
            argv=["ls", "-la"],
            classification=Classification.READONLY,
            matched_rule="ls",
            inner_commands=[],
        )
        result = CommandResult(
            command=["git", "push"],
            argv=["git", "push", "--force"],
            classification=Classification.DANGEROUS,
            matched_rule="git.push",
            inner_commands=[inner],
            ignored_options=["--context=prod"],
            remaining_options=["--unknown"],
            classification_reason="overridden by option --force to DANGEROUS",
            overriding_option="--force",
        )
        d = _command_to_dict(result)
        assert d["command"] == ["git", "push"]
        assert d["argv"] == ["git", "push", "--force"]
        assert d["classification"] == "DANGEROUS"
        assert d["matched_rule"] == "git.push"
        assert d["ignored_options"] == ["--context=prod"]
        assert d["remaining_options"] == ["--unknown"]
        assert d["classification_reason"] == "overridden by option --force to DANGEROUS"
        assert d["overriding_option"] == "--force"
        assert len(d["inner_commands"]) == 1

    def test_all_optional_fields_empty_omitted(self) -> None:
        result = CommandResult(
            command=["ls"],
            argv=["ls"],
            classification=Classification.READONLY,
            matched_rule="ls",
            inner_commands=[],
            ignored_options=None,
            remaining_options=None,
            classification_reason=None,
            overriding_option=None,
        )
        d = _command_to_dict(result)
        assert "ignored_options" not in d
        assert "remaining_options" not in d
        assert "classification_reason" not in d
        assert "overriding_option" not in d
        # inner_commands is always present (even if empty)
        assert d["inner_commands"] == []


class TestInnerCommandToDict:
    def test_with_delegation_mode_and_source(self) -> None:
        inner = InnerCommandResult(
            delegation_mode="rest_are_argv",
            delegation_source="sudo",
            command=["rm"],
            argv=["rm", "-rf", "/"],
            classification=Classification.DANGEROUS,
            matched_rule="rm",
            inner_commands=[],
        )
        d = _inner_command_to_dict(inner)
        assert d["delegation_mode"] == "rest_are_argv"
        assert d["delegation_source"] == "sudo"
        assert d["command"] == ["rm"]
        assert d["argv"] == ["rm", "-rf", "/"]
        assert d["classification"] == "DANGEROUS"
        assert d["matched_rule"] == "rm"
        assert d["inner_commands"] == []


class TestResultToDict:
    def test_with_redirects_and_parse_warnings(self) -> None:
        redirect = Redirect(operator=">", target="out.txt", affects_classification=True)
        cmd = CommandResult(
            command=["echo"],
            argv=["echo", "hello"],
            classification=Classification.EXTERNAL_EFFECTS,
            matched_rule="echo",
            inner_commands=[],
            classification_reason="elevated by output redirect",
        )
        result = ExpressionResult(
            expression="echo hello > out.txt",
            classification=Classification.EXTERNAL_EFFECTS,
            directories=[],
            commands=[cmd],
            redirects=[redirect],
            parse_warnings=["some warning"],
        )
        d = _result_to_dict(result)
        assert d["expression"] == "echo hello > out.txt"
        assert d["classification"] == "EXTERNAL_EFFECTS"
        assert "redirects" in d
        assert len(d["redirects"]) == 1
        assert "parse_warnings" in d
        assert d["parse_warnings"] == ["some warning"]

    def test_empty_redirects_and_warnings_omitted(self) -> None:
        cmd = CommandResult(
            command=["ls"],
            argv=["ls"],
            classification=Classification.READONLY,
            matched_rule="ls",
            inner_commands=[],
        )
        result = ExpressionResult(
            expression="ls",
            classification=Classification.READONLY,
            directories=[],
            commands=[cmd],
            redirects=[],
            parse_warnings=[],
        )
        d = _result_to_dict(result)
        assert "redirects" not in d
        assert "parse_warnings" not in d


class TestClassificationSerializesAsString:
    def test_classification_enum_serializes_as_string(self) -> None:
        result = CommandResult(
            command=["ls"],
            argv=["ls"],
            classification=Classification.READONLY,
            matched_rule="ls",
            inner_commands=[],
        )
        d = _command_to_dict(result)
        assert d["classification"] == "READONLY"
        assert isinstance(d["classification"], str)
        # Ensure it's not "Classification.READONLY"
        assert "Classification." not in d["classification"]

    def test_all_classification_values_serialize_correctly(self) -> None:
        for cls in Classification:
            result = CommandResult(
                command=["x"],
                argv=["x"],
                classification=cls,
                matched_rule=None,
                inner_commands=[],
            )
            d = _command_to_dict(result)
            assert d["classification"] == cls.value
            assert "." not in d["classification"]

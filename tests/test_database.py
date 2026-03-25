"""Tests for command database loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from bash_classify.database import load_database
from bash_classify.models import Classification, CommandDef, DelegationMode


class TestDatabaseLoading:
    def test_load_all_yaml_files_succeeds(self, database: dict[str, CommandDef]) -> None:
        """All YAML files in commands/ load without errors."""
        assert len(database) > 0

    def test_all_entries_are_command_defs(self, database: dict[str, CommandDef]) -> None:
        for name, cmd_def in database.items():
            assert isinstance(cmd_def, CommandDef), f"{name} is not a CommandDef"
            assert cmd_def.command == name


class TestKubectlYaml:
    def test_kubectl_exists(self, database: dict[str, CommandDef]) -> None:
        assert "kubectl" in database

    def test_kubectl_global_options_context(self, database: dict[str, CommandDef]) -> None:
        kubectl = database["kubectl"]
        assert "--context" in kubectl.global_options
        assert kubectl.global_options["--context"].takes_value is True

    def test_kubectl_global_options_namespace(self, database: dict[str, CommandDef]) -> None:
        kubectl = database["kubectl"]
        assert "--namespace" in kubectl.global_options
        assert kubectl.global_options["--namespace"].takes_value is True
        assert "-n" in kubectl.global_options["--namespace"].aliases

    def test_kubectl_alias_resolution_n(self, database: dict[str, CommandDef]) -> None:
        """Alias -n should resolve to the same OptionDef as --namespace."""
        kubectl = database["kubectl"]
        assert "-n" in kubectl.global_options
        assert kubectl.global_options["-n"] is kubectl.global_options["--namespace"]

    def test_kubectl_subcommand_get(self, database: dict[str, CommandDef]) -> None:
        kubectl = database["kubectl"]
        assert "get" in kubectl.subcommands
        assert kubectl.subcommands["get"].classification == Classification.READONLY

    def test_kubectl_subcommand_delete(self, database: dict[str, CommandDef]) -> None:
        kubectl = database["kubectl"]
        assert "delete" in kubectl.subcommands
        assert kubectl.subcommands["delete"].classification == Classification.DANGEROUS

    def test_kubectl_subcommand_exec(self, database: dict[str, CommandDef]) -> None:
        kubectl = database["kubectl"]
        assert "exec" in kubectl.subcommands
        assert kubectl.subcommands["exec"].classification == Classification.DANGEROUS


class TestGitYaml:
    def test_git_exists(self, database: dict[str, CommandDef]) -> None:
        assert "git" in database

    def test_git_global_option_c_captures_directory(self, database: dict[str, CommandDef]) -> None:
        git = database["git"]
        assert "-C" in git.global_options
        assert git.global_options["-C"].takes_value is True
        assert git.global_options["-C"].captures_directory is True

    def test_git_subcommand_status(self, database: dict[str, CommandDef]) -> None:
        git = database["git"]
        assert "status" in git.subcommands
        assert git.subcommands["status"].classification == Classification.READONLY

    def test_git_subcommand_push(self, database: dict[str, CommandDef]) -> None:
        git = database["git"]
        push = git.subcommands["push"]
        assert push.classification == Classification.WRITE
        assert "--force" in push.options
        assert push.options["--force"].overrides == Classification.DANGEROUS


class TestFindYaml:
    def test_find_base_classification(self, database: dict[str, CommandDef]) -> None:
        find = database["find"]
        assert find.classification == Classification.READONLY

    def test_find_strict_false(self, database: dict[str, CommandDef]) -> None:
        find = database["find"]
        assert find.strict is False

    def test_find_exec_delegates_to_terminated_argv(self, database: dict[str, CommandDef]) -> None:
        find = database["find"]
        exec_opt = find.options["-exec"]
        assert exec_opt.delegates_to is not None
        assert exec_opt.delegates_to.mode == DelegationMode.TERMINATED_ARGV
        assert exec_opt.delegates_to.terminator == ";"

    def test_find_delete_overrides_dangerous(self, database: dict[str, CommandDef]) -> None:
        find = database["find"]
        assert "-delete" in find.options
        assert find.options["-delete"].overrides == Classification.DANGEROUS


class TestXargsYaml:
    def test_xargs_delegates_to_rest_are_argv(self, database: dict[str, CommandDef]) -> None:
        xargs = database["xargs"]
        assert xargs.delegates_to is not None
        assert xargs.delegates_to.mode == DelegationMode.REST_ARE_ARGV


class TestShYaml:
    def test_sh_delegates_to_flag_value_is_expression(self, database: dict[str, CommandDef]) -> None:
        sh = database["sh"]
        assert sh.delegates_to is not None
        assert sh.delegates_to.mode == DelegationMode.FLAG_VALUE_IS_EXPRESSION
        assert sh.delegates_to.flag == "-c"


class TestSudoYaml:
    def test_sudo_delegates_to_rest_are_argv_with_min_classification(self, database: dict[str, CommandDef]) -> None:
        sudo = database["sudo"]
        assert sudo.delegates_to is not None
        assert sudo.delegates_to.mode == DelegationMode.REST_ARE_ARGV
        assert sudo.delegates_to.min_classification == Classification.WRITE


class TestEnvYaml:
    def test_env_delegates_to_rest_are_argv_with_strip_assignments(self, database: dict[str, CommandDef]) -> None:
        env = database["env"]
        assert env.delegates_to is not None
        assert env.delegates_to.mode == DelegationMode.REST_ARE_ARGV
        assert env.delegates_to.strip_assignments is True


class TestDatabaseErrorHandling:
    def test_invalid_yaml_includes_filename(self, tmp_path: Path) -> None:
        """Loading a malformed YAML file should raise ValueError with the filename."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("command: test\nclassification: INVALID_VALUE\n")
        with pytest.raises(ValueError, match="bad.yaml"):
            load_database(tmp_path)

    def test_missing_command_key_includes_filename(self, tmp_path: Path) -> None:
        """Loading a YAML file without 'command' key should raise ValueError with the filename."""
        bad_file = tmp_path / "nocommand.yaml"
        bad_file.write_text("classification: READONLY\n")
        with pytest.raises(ValueError, match="nocommand.yaml"):
            load_database(tmp_path)


class TestEmptyAndNonDictYamlFiles:
    def test_empty_yaml_file_skipped(self, tmp_path: Path) -> None:
        """An empty YAML file should be skipped (yaml.safe_load returns None)."""
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")

        valid_file = tmp_path / "echo.yaml"
        valid_file.write_text("command: echo\nclassification: READONLY\n")

        db = load_database(tmp_path)
        assert "echo" in db
        assert len(db) == 1

    def test_list_yaml_raises_valueerror(self, tmp_path: Path) -> None:
        """A YAML file containing a list should raise ValueError with filename."""
        list_file = tmp_path / "badlist.yaml"
        list_file.write_text("- item1\n- item2\n")

        with pytest.raises(ValueError, match="badlist.yaml"):
            load_database(tmp_path)


class TestStrictDefault:
    def test_strict_defaults_to_true(self, database: dict[str, CommandDef]) -> None:
        """Commands without explicit strict: false should default to strict: true."""
        kubectl = database["kubectl"]
        # kubectl itself has explicit strict: false for unknown subcommand fallback
        assert kubectl.strict is False
        # kubectl.top has no strict: false, so it should be True (default)
        assert kubectl.subcommands["top"].strict is True

    def test_strict_false_on_find(self, database: dict[str, CommandDef]) -> None:
        find = database["find"]
        assert find.strict is False

    def test_strict_false_on_grep(self, database: dict[str, CommandDef]) -> None:
        grep = database["grep"]
        assert grep.strict is False

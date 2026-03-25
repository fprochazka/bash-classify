"""Tests for command database loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from bash_classify.database import get_default_commands_dir, load_database
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
        assert push.classification == Classification.EXTERNAL_EFFECTS
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
        assert sudo.delegates_to.min_classification == Classification.DANGEROUS


class TestEnvYaml:
    def test_env_delegates_to_rest_are_argv_with_strip_assignments(self, database: dict[str, CommandDef]) -> None:
        env = database["env"]
        assert env.delegates_to is not None
        assert env.delegates_to.mode == DelegationMode.REST_ARE_ARGV
        assert env.delegates_to.strip_assignments is True


class TestDatabaseErrorHandling:
    def test_invalid_yaml_includes_filename(self, tmp_path: Path) -> None:
        """Accessing a malformed YAML command should raise ValueError with the filename."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("command: test\nclassification: INVALID_VALUE\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="bad.yaml"):
            db["bad"]

    def test_missing_command_key_includes_filename(self, tmp_path: Path) -> None:
        """Accessing a YAML command without 'command' key should raise ValueError with the filename."""
        bad_file = tmp_path / "nocommand.yaml"
        bad_file.write_text("classification: READONLY\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="nocommand.yaml"):
            db["nocommand"]


class TestEmptyAndNonDictYamlFiles:
    def test_empty_yaml_file_raises_on_access(self, tmp_path: Path) -> None:
        """An empty YAML file should raise ValueError when accessed (lazy loading)."""
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")

        valid_file = tmp_path / "echo.yaml"
        valid_file.write_text("command: echo\nclassification: READONLY\n")

        db = load_database(tmp_path)
        assert "echo" in db
        assert "empty" in db  # indexed by filename
        assert len(db) == 2  # both files indexed
        # Valid file loads fine
        assert db["echo"].classification == Classification.READONLY
        # Empty file raises on access
        with pytest.raises(ValueError, match="empty.yaml"):
            db["empty"]

    def test_list_yaml_raises_valueerror_on_access(self, tmp_path: Path) -> None:
        """A YAML file containing a list should raise ValueError when accessed."""
        list_file = tmp_path / "badlist.yaml"
        list_file.write_text("- item1\n- item2\n")

        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="badlist.yaml"):
            db["badlist"]


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


class TestUserCommandsDir:
    def test_user_override_replaces_builtin(self, tmp_path: Path) -> None:
        """User YAML overrides built-in command definition."""
        user_dir = tmp_path / "config" / "commands"
        user_dir.mkdir(parents=True)
        (user_dir / "grep.yaml").write_text("command: grep\nclassification: EXTERNAL_EFFECTS\nstrict: false\n")

        import os

        old = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
        try:
            os.environ["BASH_CLASSIFY_CONFIG_DIR"] = str(tmp_path / "config")
            db = load_database()
            assert db["grep"].classification == Classification.EXTERNAL_EFFECTS  # overridden
        finally:
            if old is None:
                os.environ.pop("BASH_CLASSIFY_CONFIG_DIR", None)
            else:
                os.environ["BASH_CLASSIFY_CONFIG_DIR"] = old

    def test_user_adds_new_command(self, tmp_path: Path) -> None:
        """User YAML adds a command not in built-in database."""
        user_dir = tmp_path / "config" / "commands"
        user_dir.mkdir(parents=True)
        (user_dir / "mycustomtool.yaml").write_text("command: mycustomtool\nclassification: READONLY\nstrict: false\n")

        import os

        old = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
        try:
            os.environ["BASH_CLASSIFY_CONFIG_DIR"] = str(tmp_path / "config")
            db = load_database()
            assert "mycustomtool" in db
            assert db["mycustomtool"].classification == Classification.READONLY
        finally:
            if old is None:
                os.environ.pop("BASH_CLASSIFY_CONFIG_DIR", None)
            else:
                os.environ["BASH_CLASSIFY_CONFIG_DIR"] = old

    def test_missing_user_dir_is_silently_skipped(self, tmp_path: Path) -> None:
        """Non-existent user config dir doesn't cause errors."""
        import os

        old = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
        try:
            os.environ["BASH_CLASSIFY_CONFIG_DIR"] = str(tmp_path / "nonexistent")
            db = load_database()
            assert len(db) > 0  # Built-in commands still loaded
        finally:
            if old is None:
                os.environ.pop("BASH_CLASSIFY_CONFIG_DIR", None)
            else:
                os.environ["BASH_CLASSIFY_CONFIG_DIR"] = old

    def test_explicit_commands_dir_skips_user_overrides(self, tmp_path: Path) -> None:
        """When explicit commands_dir is passed, user overrides are NOT loaded."""
        user_dir = tmp_path / "config" / "commands"
        user_dir.mkdir(parents=True)
        (user_dir / "grep.yaml").write_text("command: grep\nclassification: DANGEROUS\nstrict: false\n")

        import os

        old = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
        try:
            os.environ["BASH_CLASSIFY_CONFIG_DIR"] = str(tmp_path / "config")
            # Pass explicit dir — user overrides should NOT be loaded
            db = load_database(get_default_commands_dir())
            assert db["grep"].classification == Classification.READONLY  # built-in, not overridden
        finally:
            if old is None:
                os.environ.pop("BASH_CLASSIFY_CONFIG_DIR", None)
            else:
                os.environ["BASH_CLASSIFY_CONFIG_DIR"] = old

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


class TestAliasOf:
    def test_alias_file_parses(self, tmp_path: Path) -> None:
        """An alias file produces a CommandDef with alias_of set."""
        target = tmp_path / "target.yaml"
        target.write_text("command: target\nclassification: READONLY\n")
        alias = tmp_path / "myalias.yaml"
        alias.write_text("command: myalias\ndescription: pointer\nalias_of: target\n")

        db = load_database(tmp_path)
        alias_def = db["myalias"]
        assert alias_def.alias_of == "target"
        assert alias_def.command == "myalias"
        assert alias_def.classification is None
        assert alias_def.subcommands == {}

    def test_alias_file_with_subcommands_raises(self, tmp_path: Path) -> None:
        """An alias file combined with classification-bearing fields is rejected."""
        alias = tmp_path / "bad.yaml"
        alias.write_text("command: bad\nalias_of: target\nsubcommands:\n  sub: {classification: READONLY}\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="subcommands"):
            db["bad"]

    def test_alias_file_with_classification_raises(self, tmp_path: Path) -> None:
        alias = tmp_path / "bad.yaml"
        alias.write_text("command: bad\nalias_of: target\nclassification: READONLY\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="classification"):
            db["bad"]

    def test_alias_file_only_command_description_alias_of_is_valid(self, tmp_path: Path) -> None:
        target = tmp_path / "target.yaml"
        target.write_text("command: target\nclassification: READONLY\n")
        alias = tmp_path / "myalias.yaml"
        alias.write_text('command: myalias\ndescription: "some desc"\nalias_of: target\n')
        db = load_database(tmp_path)
        assert db["myalias"].alias_of == "target"


class TestSubcommandAliases:
    def test_alias_maps_to_the_same_definition_object(self, database: dict[str, CommandDef]) -> None:
        """`glab pipe` and `glab pipeline` are glab's own deprecated names for `glab ci`."""
        glab = database["glab"]
        ci = glab.subcommands["ci"]
        assert glab.subcommands["pipe"] is ci
        assert glab.subcommands["pipeline"] is ci

    def test_alias_keeps_the_canonical_name(self, database: dict[str, CommandDef]) -> None:
        glab = database["glab"]
        assert glab.subcommands["pipeline"].command == "ci"
        assert glab.subcommands["ci"].aliases == ["pipe", "pipeline"]

    def test_subcommand_without_aliases_has_an_empty_list(self, database: dict[str, CommandDef]) -> None:
        assert database["glab"].subcommands["mr"].aliases == []

    def test_nested_alias_is_registered(self, tmp_path: Path) -> None:
        """Aliases work at any depth, not only on the first level."""
        (tmp_path / "tool.yaml").write_text(
            "command: tool\n"
            "subcommands:\n"
            "  remote:\n"
            "    subcommands:\n"
            "      list:\n"
            "        aliases: [ls]\n"
            "        classification: READONLY\n"
        )
        db = load_database(tmp_path)
        remote = db["tool"].subcommands["remote"]
        assert remote.subcommands["ls"] is remote.subcommands["list"]

    def test_alias_colliding_with_a_sibling_subcommand_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text(
            "command: tool\nsubcommands:\n  ci:\n    aliases: [status]\n  status:\n    classification: READONLY\n"
        )
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*alias 'status'.*already a subcommand"):
            db["tool"]

    def test_alias_claimed_by_two_siblings_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text(
            "command: tool\nsubcommands:\n  ci:\n    aliases: [p]\n  publish:\n    aliases: [p]\n"
        )
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*alias 'p'.*already an alias of subcommand 'ci'"):
            db["tool"]

    def test_alias_repeating_its_own_subcommand_name_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nsubcommands:\n  ci:\n    aliases: [ci]\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*alias 'ci'.*already a subcommand"):
            db["tool"]

    def test_top_level_aliases_key_is_rejected(self, tmp_path: Path) -> None:
        """A command file names itself by its filename; a second name is an alias_of file."""
        (tmp_path / "tool.yaml").write_text("command: tool\naliases: [t]\nclassification: READONLY\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*'aliases' is only valid on subcommands"):
            db["tool"]

    def test_aliases_must_be_a_list(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nsubcommands:\n  ci:\n    aliases: pipe\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*'aliases' must be a list"):
            db["tool"]


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


class TestTheSuiteIsIsolatedFromTheUserDatabase:
    """The suite must answer from this repository alone, never from the machine running it.

    `~/.config/bash-classify/commands/` is read by every bare `load_database()`, so without
    isolation the suite's result depends on files that are not in the repository -- and those
    files are the machine owner's own tooling, which a failed assertion would print into
    pytest output and CI logs. `tests/conftest.py` points the whole session at an empty config
    directory; these pin that it is actually in effect, because every other test in the suite
    passes either way on a machine whose user database happens to agree with the bundled one.
    """

    def test_the_config_dir_in_effect_is_empty(self) -> None:
        import os

        config_dir = Path(os.environ["BASH_CLASSIFY_CONFIG_DIR"])
        assert config_dir.is_dir()
        assert not (config_dir / "commands").exists()
        assert not (config_dir / "sensitive-paths.yaml").exists()

    def test_a_bare_load_database_sees_exactly_the_bundled_files(self) -> None:
        bundled = {yaml_file.stem for yaml_file in get_default_commands_dir().glob("*.yaml")}
        assert set(load_database()) == bundled

    def test_the_database_fixture_sees_exactly_the_bundled_files(self, database: dict[str, CommandDef]) -> None:
        bundled = {yaml_file.stem for yaml_file in get_default_commands_dir().glob("*.yaml")}
        assert set(database) == bundled

    def test_the_database_fixture_ignores_the_environment_entirely(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even pointed at a populated user database, the fixture resolves the bundled files."""
        user_dir = tmp_path / "config" / "commands"
        user_dir.mkdir(parents=True)
        (user_dir / "zzdemotool.yaml").write_text("command: zzdemotool\nclassification: READONLY\n")
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path / "config"))

        assert "zzdemotool" in load_database()  # the environment is honoured where it is asked for
        assert "zzdemotool" not in load_database(get_default_commands_dir())


class TestOutputPathOptions:
    """Options the tool documents as naming a file it writes."""

    def test_curl_output(self, database: dict[str, CommandDef]) -> None:
        assert database["curl"].options["-o"].names_output_path is True
        assert database["curl"].options["--output"].names_output_path is True

    def test_curl_upload_file_is_a_read(self, database: dict[str, CommandDef]) -> None:
        """`curl -T` sends the named file to the server; nothing local is written."""
        assert database["curl"].options["-T"].names_output_path is False

    def test_wget_output_document(self, database: dict[str, CommandDef]) -> None:
        assert database["wget"].options["-O"].names_output_path is True
        assert database["wget"].options["--output-document"].names_output_path is True

    def test_cp_and_mv_target_directory(self, database: dict[str, CommandDef]) -> None:
        for command in ("cp", "mv"):
            assert database[command].options["-t"].names_output_path is True
            assert database[command].options["--target-directory"].names_output_path is True

    def test_sort_output(self, database: dict[str, CommandDef]) -> None:
        assert database["sort"].options["-o"].names_output_path is True

    def test_git_clone_separate_git_dir(self, database: dict[str, CommandDef]) -> None:
        clone = database["git"].subcommands["clone"]
        assert clone.options["--separate-git-dir"].names_output_path is True

    def test_tar_file_is_not_marked(self, database: dict[str, CommandDef]) -> None:
        """`tar -f` writes the archive when creating and reads it when extracting."""
        assert database["tar"].options["-f"].names_output_path is False


class TestExtractionDestinations:
    """Options whose value is the directory an archive or download lands in."""

    def test_unzip_destination(self, database: dict[str, CommandDef]) -> None:
        assert database["unzip"].options["-d"].takes_value is True
        assert database["unzip"].options["-d"].captures_directory is True

    def test_tar_destination(self, database: dict[str, CommandDef]) -> None:
        assert database["tar"].options["-C"].captures_directory is True
        assert database["tar"].options["--directory"].captures_directory is True

    def test_wget_directory_prefix(self, database: dict[str, CommandDef]) -> None:
        assert database["wget"].options["-P"].captures_directory is True
        assert database["wget"].options["--directory-prefix"].captures_directory is True


class TestLazyDatabaseViews:
    """`CommandDatabase` populates lazily, so `dict`'s own views would report only what was read.

    `len()`, `in` and `[key]` were already right; `.items()`, `.values()` and `.keys()` read the
    underlying storage and came back empty on a fresh instance. A consumer iterating the database
    to build a report got nothing and no error.
    """

    def test_views_see_every_command_before_anything_is_read(self) -> None:
        database = load_database()
        assert len(database.items()) == len(database)
        assert len(database.values()) == len(database)
        assert len(database.keys()) == len(database)

    def test_items_resolve_to_definitions(self) -> None:
        database = load_database()
        by_name = dict(database.items())
        assert by_name["git"].command == "git"
        assert {name for name, _ in database.items()} == set(database)


class TestLazyDatabaseBehavesLikeADict:
    """The laziness must not be visible through any dict operation, not only the views.

    `copy()` returned `{}`, `== {}` was True while `len()` said 168, `pop("git")` raised
    KeyError while `"git" in db` was True, and `popitem()` and `reversed()` were empty. Each of
    those reads the underlying storage, which holds only what has been parsed so far.
    """

    def test_equality_is_asked_before_anything_is_read(self) -> None:
        """On a fresh instance the cache is empty, so `dict.__eq__` would call it equal to `{}`."""
        assert load_database() != {}
        assert load_database().__eq__({}) is False

    def test_copy_and_equality_see_everything(self) -> None:
        database = load_database()
        assert len(database.copy()) == len(database)
        assert database == dict(database.items())

    def test_pop_and_delete_work_on_an_unread_command(self) -> None:
        database = load_database()
        size = len(database)
        assert "git" in database
        assert database.pop("git").command == "git"
        assert "git" not in database
        assert len(database) == size - 1
        assert database.pop("git", None) is None

    def test_popitem_and_reversed_see_unread_commands(self) -> None:
        database = load_database()
        key, value = database.popitem()
        assert isinstance(value, CommandDef)
        assert key not in database
        assert list(reversed(load_database())) == list(reversed(list(load_database())))

    def test_the_unoverridden_half_of_dict_is_documented_not_fixed(self) -> None:
        """The class docstring names what is index-backed; this pins the boundary it draws.

        `update`, `|` and `repr` are C implementations that bypass `__setitem__` and read the
        cache, and the docstring says so rather than claiming the class is a dict. A caller who
        needs them is told to build a plain dict with `dict(db.items())` first.
        """
        database = load_database()
        assert repr(database) == "{}"
        database.update({"zzz-not-real": CommandDef(command="zzz-not-real")})
        assert "zzz-not-real" not in list(database)
        assert dict(load_database().items())["git"].command == "git"

    def test_assignment_registers_the_command(self) -> None:
        database = load_database()
        database["zzz-not-a-real-command"] = CommandDef(command="zzz-not-a-real-command")
        assert "zzz-not-a-real-command" in list(database)
        assert "zzz-not-a-real-command" in dict(database.items())
        assert database["zzz-not-a-real-command"].command == "zzz-not-a-real-command"

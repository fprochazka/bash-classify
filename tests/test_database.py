"""Tests for command database loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from bash_classify.database import get_default_commands_dir, load_database
from bash_classify.models import Classification, CommandDef, DelegationMode, Risk


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


class TestUnknownKeysAreRejected:
    """A key the loader does not know is a typo, and a silent typo is the dangerous kind.

    Only the bundled files are schema-validated in CI; a user database is read by this loader
    alone. `clasification: READONLY` used to leave the command at its default and say nothing,
    and the misspelling of a key that lowers a classification fails in the unsafe direction.
    """

    def test_unknown_command_level_key_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nclasification: READONLY\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*command 'tool'.*unknown field.*clasification"):
            db["tool"]

    def test_the_message_lists_the_accepted_keys(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nclasification: READONLY\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="accepted:.*classification.*"):
            db["tool"]

    def test_unknown_subcommand_level_key_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nsubcommands:\n  sub:\n    riskk: LOW\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*subcommand 'sub'.*unknown field.*riskk"):
            db["tool"]

    def test_a_subcommand_may_not_carry_command_level_only_keys(self, tmp_path: Path) -> None:
        """`global_options` belongs to the binary; under a subcommand it would never be read."""
        (tmp_path / "tool.yaml").write_text("command: tool\nsubcommands:\n  sub:\n    global_options:\n      -x: {}\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="subcommand 'sub'.*unknown field.*global_options"):
            db["tool"]

    def test_unknown_option_level_key_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\noptions:\n  -i: {overides: DANGEROUS}\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*option '-i'.*unknown field.*overides"):
            db["tool"]

    def test_unknown_global_option_level_key_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nglobal_options:\n  -i: {takes_values: true}\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="option '-i'.*unknown field.*takes_values"):
            db["tool"]

    def test_unknown_delegation_key_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\ndelegates_to:\n  mode: rest_are_argv\n  seperator: --\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*delegates_to.*unknown field.*seperator"):
            db["tool"]

    def test_a_non_mapping_options_container_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\noptions:\n  - -i\n  - -v\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*'options' must be a mapping.*got list"):
            db["tool"]

    def test_a_non_mapping_global_options_container_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nglobal_options:\n  - -i\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="'global_options' must be a mapping.*got list"):
            db["tool"]

    def test_a_non_mapping_subcommands_container_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nsubcommands:\n  - push\n  - pull\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="'subcommands' must be a mapping.*got list"):
            db["tool"]

    def test_an_empty_delegates_to_block_is_rejected(self, tmp_path: Path) -> None:
        """An absent key says "does not delegate"; an empty block must not say it by accident.

        The schema has always required `mode`, so this is the loader agreeing with it. It
        matters because the parser used to return None for any falsy value, which is the same
        answer as "no delegation" -- and losing a delegation always lowers the verdict.
        """
        (tmp_path / "tool.yaml").write_text("command: tool\ndelegates_to: {}\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="tool.yaml.*delegates_to.*missing required field 'mode'"):
            db["tool"]

    def test_an_empty_list_delegates_to_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\ndelegates_to: []\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="delegates_to.*expected a mapping, got list"):
            db["tool"]

    def test_an_empty_delegates_to_on_an_option_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\noptions:\n  -exec: {delegates_to: {}}\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="delegates_to.*missing required field 'mode'"):
            db["tool"]

    def test_an_absent_delegates_to_is_still_how_a_command_says_it_does_not_delegate(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nclassification: READONLY\n")
        assert load_database(tmp_path)["tool"].delegates_to is None

    def test_a_non_mapping_delegates_to_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\ndelegates_to:\n  - rest_are_argv\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="delegates_to.*expected a mapping, got list"):
            db["tool"]

    def test_a_non_mapping_subcommand_entry_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "tool.yaml").write_text("command: tool\nsubcommands:\n  sub: READONLY\n")
        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="subcommand 'sub'.*expected a mapping, got str"):
            db["tool"]

    def test_every_bundled_file_still_loads(self, database: dict[str, CommandDef]) -> None:
        """The allowlists mirror the schema, so the bundled database must pass them unchanged."""
        assert all(isinstance(definition, CommandDef) for definition in database.values())


@pytest.fixture
def user_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A user command database at `$BASH_CLASSIFY_CONFIG_DIR/commands`, never the real one."""
    commands = tmp_path / "config" / "commands"
    commands.mkdir(parents=True)
    monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path / "config"))
    return commands


class TestUserFileReplacesByDefault:
    """A user file without `extends` keeps the behaviour it has always had: full replacement."""

    def test_replacement_drops_every_bundled_subcommand(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text("command: git\nclassification: READONLY\nstrict: false\n")

        git = load_database()["git"]
        assert git.classification == Classification.READONLY
        assert git.subcommands == {}
        assert git.global_options == {}

    def test_replacement_drops_bundled_options(self, user_config_dir: Path) -> None:
        (user_config_dir / "curl.yaml").write_text("command: curl\nclassification: READONLY\nstrict: false\n")

        assert load_database()["curl"].options == {}


class TestExtendsBuiltin:
    """`extends: builtin` merges a user file over the bundled definition of the same name."""

    def test_user_subcommand_is_added_and_bundled_ones_survive(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {classification: LOCAL_EFFECTS, risk: LOW}\n"
        )

        git = load_database()["git"]
        assert git.subcommands["zzdemo"].classification == Classification.LOCAL_EFFECTS
        assert git.subcommands["zzdemo"].risk == Risk.LOW
        assert git.subcommands["status"].classification == Classification.READONLY
        assert git.subcommands["push"].classification == Classification.EXTERNAL_EFFECTS

    def test_bundled_base_fields_survive_when_the_user_file_is_silent(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {classification: READONLY}\n"
        )

        git = load_database()["git"]
        assert git.classification == Classification.DANGEROUS  # the bundled base, untouched
        assert "-C" in git.global_options
        assert git.global_options["-C"].captures_directory is True

    def test_top_level_scalars_are_overridden_when_the_user_file_names_them(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nclassification: LOCAL_EFFECTS\n")

        git = load_database()["git"]
        assert git.classification == Classification.LOCAL_EFFECTS
        assert git.subcommands["push"].classification == Classification.EXTERNAL_EFFECTS

    def test_a_subcommand_in_both_files_merges_field_by_field(self, user_config_dir: Path) -> None:
        """Naming one field must not silently delete the rest of the bundled subcommand."""
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nsubcommands:\n  push: {risk: LOW}\n")

        push = load_database()["git"].subcommands["push"]
        assert push.risk == Risk.LOW  # the user's field
        assert push.classification == Classification.EXTERNAL_EFFECTS  # the bundled one
        assert push.options["--force"].overrides == Classification.DANGEROUS  # still dangerous

    def test_a_nested_subcommand_in_both_files_merges_too(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\n"
            "subcommands:\n  remote:\n    subcommands:\n      zzdemo: {classification: READONLY}\n"
        )

        remote = load_database()["git"].subcommands["remote"]
        assert remote.subcommands["zzdemo"].classification == Classification.READONLY
        assert "add" in remote.subcommands  # the bundled nested subcommands survive

    def test_options_merge_and_a_named_option_keeps_its_bundled_fields(self, user_config_dir: Path) -> None:
        (user_config_dir / "find.yaml").write_text(
            "command: find\nextends: builtin\noptions:\n  -delete: {risk: HIGH}\n  -zzdemo: {takes_value: true}\n"
        )

        find = load_database()["find"]
        assert find.options["-delete"].risk == Risk.HIGH  # the user's field
        assert find.options["-delete"].overrides == Classification.DANGEROUS  # the bundled one
        assert find.options["-zzdemo"].takes_value is True  # purely additional
        assert find.options["-exec"].delegates_to is not None  # every other bundled option survives

    def test_an_option_is_overridden_under_the_primary_name_the_bundled_file_uses(self, user_config_dir: Path) -> None:
        """`curl` files `-o` as its own entry and again as an alias of `--output`, which wins.

        That is how `_parse_options` has always resolved a bundled file, extended or not, so
        an override goes on the name the later entry owns.
        """
        (user_config_dir / "curl.yaml").write_text(
            "command: curl\nextends: builtin\noptions:\n  --output: {risk: HIGH}\n"
        )

        curl = load_database()["curl"]
        assert curl.options["--output"].risk == Risk.HIGH
        assert curl.options["-o"] is curl.options["--output"]
        assert curl.options["--output"].names_output_path is True  # the bundled fields survive

    def test_global_options_merge(self, user_config_dir: Path) -> None:
        (user_config_dir / "kubectl.yaml").write_text(
            "command: kubectl\nextends: builtin\nglobal_options:\n  --zzdemo: {takes_value: true}\n"
        )

        kubectl = load_database()["kubectl"]
        assert kubectl.global_options["--zzdemo"].takes_value is True
        assert kubectl.global_options["-n"] is kubectl.global_options["--namespace"]

    def test_an_option_written_under_a_bundled_alias_spelling_is_rejected(self, user_config_dir: Path) -> None:
        """`-n` is how the bundled file spells an alias of `--namespace`, not an option of its own.

        Aliases are expanded after the merge, so an entry added under the alias spelling is a
        separate definition built from defaults rather than a change to the bundled one. Here
        it cost `-n` its `takes_value`, `prod` filled the subcommand slot, `delete` never
        matched, and `kubectl -n prod delete pod x` fell from DANGEROUS to EXTERNAL_EFFECTS.
        """
        (user_config_dir / "kubectl.yaml").write_text(
            "command: kubectl\nextends: builtin\nglobal_options:\n  -n: {overrides: READONLY}\n"
        )

        db = load_database()
        with pytest.raises(ValueError, match="'global_options' declares '-n'.*alias of '--namespace'"):
            db["kubectl"]

    def test_the_alias_spelling_is_rejected_even_with_an_empty_body(self, user_config_dir: Path) -> None:
        (user_config_dir / "kubectl.yaml").write_text("command: kubectl\nextends: builtin\nglobal_options:\n  -n: {}\n")

        db = load_database()
        with pytest.raises(ValueError, match="write it under '--namespace' instead"):
            db["kubectl"]

    def test_an_option_the_bundled_file_files_under_both_spellings_is_rejected_too(self, user_config_dir: Path) -> None:
        """`curl` has `-o` as a key *and* as an alias of `--output`; the alias still wins."""
        (user_config_dir / "curl.yaml").write_text("command: curl\nextends: builtin\noptions:\n  -o: {risk: HIGH}\n")

        db = load_database()
        with pytest.raises(ValueError, match="'options' declares '-o'.*alias of '--output'"):
            db["curl"]

    def test_releasing_a_bundled_alias_and_keying_it_in_the_same_file_is_allowed(self, user_config_dir: Path) -> None:
        """Rewriting the alias list is how an author takes the name back, and a list replaces.

        The check has to read the claim after the user's rewrite, not before, or the one
        spelling that legitimately reassigns an alias is the one it refuses.
        """
        (user_config_dir / "kubectl.yaml").write_text(
            "command: kubectl\nextends: builtin\n"
            "global_options:\n  --namespace: {aliases: []}\n  -n: {takes_value: true}\n"
        )

        kubectl = load_database()["kubectl"]
        assert kubectl.global_options["-n"].takes_value is True
        assert kubectl.global_options["-n"] is not kubectl.global_options["--namespace"]
        assert kubectl.global_options["--namespace"].takes_value is True  # bundled fields kept
        assert "--context" in kubectl.global_options  # and the rest of the file merged

    def test_releasing_an_alias_to_a_different_option_still_catches_the_new_claim(self, user_config_dir: Path) -> None:
        (user_config_dir / "kubectl.yaml").write_text(
            "command: kubectl\nextends: builtin\n"
            "global_options:\n  --namespace: {aliases: []}\n  --context: {aliases: [-n]}\n  -n: {}\n"
        )

        db = load_database()
        with pytest.raises(ValueError, match="'-n'.*alias of '--context'"):
            db["kubectl"]

    def test_an_option_written_under_a_name_no_bundled_entry_claims_is_fine(self, user_config_dir: Path) -> None:
        (user_config_dir / "kubectl.yaml").write_text(
            "command: kubectl\nextends: builtin\nglobal_options:\n  --zzdemo: {takes_value: true}\n"
        )

        assert load_database()["kubectl"].global_options["--zzdemo"].takes_value is True

    def test_delegates_to_is_replaced_whole_not_merged(self, user_config_dir: Path) -> None:
        """`mode` decides which other fields mean anything, so half a block is not a setting."""
        (user_config_dir / "sudo.yaml").write_text(
            "command: sudo\nextends: builtin\ndelegates_to:\n  mode: after_separator\n  separator: '--'\n"
        )

        sudo = load_database()["sudo"]
        delegates_to = sudo.delegates_to
        assert delegates_to is not None
        assert delegates_to.mode == DelegationMode.AFTER_SEPARATOR
        assert delegates_to.separator == "--"
        assert delegates_to.min_classification is None  # the bundled DANGEROUS floor is gone
        # ... while the rest of the bundled file is still there, which is what makes this a
        # merge rather than the replacement a file without `extends` would have been.
        assert sudo.options["-u"].takes_value is True
        assert sudo.classification is not None

    def test_a_list_is_replaced_not_appended(self, user_config_dir: Path) -> None:
        (user_config_dir / "glab.yaml").write_text(
            "command: glab\nextends: builtin\nsubcommands:\n  ci: {aliases: [zzdemo]}\n"
        )

        glab = load_database()["glab"]
        assert glab.subcommands["ci"].aliases == ["zzdemo"]
        assert glab.subcommands["zzdemo"] is glab.subcommands["ci"]
        assert "pipeline" not in glab.subcommands
        # The list was replaced; everything around it was merged, not replaced.
        assert "mr" in glab.subcommands
        assert glab.subcommands["ci"].subcommands != {}

    def test_extending_reaches_the_classifier(self, user_config_dir: Path) -> None:
        from bash_classify import classify_expression

        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {classification: READONLY}\n"
        )

        assert classify_expression("git zzdemo").risk == Risk.LOW
        assert classify_expression("git push --force").classification == Classification.DANGEROUS


class TestExtendsErrors:
    def test_extending_a_command_with_no_bundled_definition_is_an_error(self, user_config_dir: Path) -> None:
        (user_config_dir / "zzdemotool.yaml").write_text("command: zzdemotool\nextends: builtin\n")

        db = load_database()
        with pytest.raises(ValueError, match="zzdemotool.yaml.*command 'zzdemotool'.*nothing to extend"):
            db["zzdemotool"]

    def test_the_error_names_the_file_and_the_command(self, user_config_dir: Path) -> None:
        (user_config_dir / "zzdemotool.yaml").write_text("command: zzdemotool\nextends: builtin\n")

        db = load_database()
        with pytest.raises(ValueError) as excinfo:
            db["zzdemotool"]
        assert str(user_config_dir / "zzdemotool.yaml") in str(excinfo.value)
        assert "zzdemotool" in str(excinfo.value)

    def test_a_misspelled_extends_value_is_an_error_not_a_replacement(self, user_config_dir: Path) -> None:
        """`extends: bultin` must not quietly fall back to replacing the bundled definition."""
        (user_config_dir / "git.yaml").write_text("command: git\nextends: bultin\nclassification: READONLY\n")

        db = load_database()
        with pytest.raises(ValueError, match="git.yaml.*'extends' must be 'builtin', got 'bultin'"):
            db["git"]

    def test_extends_combined_with_alias_of_is_an_error(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nalias_of: hg\n")

        db = load_database()
        with pytest.raises(ValueError, match="mutually exclusive"):
            db["git"]

    def test_extends_on_a_subcommand_is_an_unknown_key(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {extends: builtin}\n"
        )

        db = load_database()
        with pytest.raises(ValueError, match="subcommand 'zzdemo'.*unknown field.*extends"):
            db["git"]

    def test_an_explicit_commands_dir_has_no_builtin_layer_to_extend(self, tmp_path: Path) -> None:
        """`load_database(dir)` loads that directory alone, so nothing in it can extend."""
        (tmp_path / "git.yaml").write_text("command: git\nextends: builtin\n")

        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="only for a user database file.*itself the bundled definition of 'git'"):
            db["git"]

    def test_a_user_subcommand_colliding_with_a_bundled_alias_is_rejected(self, user_config_dir: Path) -> None:
        """`pipeline` is a bundled alias of `glab ci`; claiming it too has to be said out loud."""
        (user_config_dir / "glab.yaml").write_text(
            "command: glab\nextends: builtin\nsubcommands:\n  pipeline: {classification: READONLY}\n"
        )

        db = load_database()
        with pytest.raises(ValueError, match="alias 'pipeline'.*already a subcommand"):
            db["glab"]

    def test_the_collision_is_resolved_by_overriding_the_bundled_aliases(self, user_config_dir: Path) -> None:
        (user_config_dir / "glab.yaml").write_text(
            "command: glab\nextends: builtin\n"
            "subcommands:\n  ci: {aliases: [pipe]}\n  pipeline: {classification: READONLY}\n"
        )

        glab = load_database()["glab"]
        assert glab.subcommands["pipeline"].classification == Classification.READONLY
        assert glab.subcommands["pipe"] is glab.subcommands["ci"]
        # And the bundled file is still underneath both of them.
        assert "mr" in glab.subcommands
        assert glab.subcommands["ci"].subcommands != {}

    def test_no_bundled_file_declares_extends(self) -> None:
        """`extends` is a user-database key; a bundled file has nothing above it to extend."""
        import yaml

        for yaml_file in sorted(get_default_commands_dir().glob("*.yaml")):
            with open(yaml_file) as handle:
                assert "extends" not in yaml.safe_load(handle), yaml_file


class TestExtendsRejectsABlankValue:
    """A key written with no value must not quietly delete the bundled one.

    YAML reads `classification:` with nothing after it as `None`, and every parser below reads
    `None` as "not set, use the default". In an extending file that overwrote the bundled value
    and fell back to a default that is always the weaker answer, so half a line typed -- or a
    value commented out while its author thinks -- silently turned a bundled protection into an
    auto-approve. Measured before the fix, against the same expression with no user file at all:

        classification:                 git zzunknown          DANGEROUS HIGH -> READONLY LOW
        subcommands:\n  push:           git push origin main   EXTERNAL  MED  -> READONLY LOW
        delegates_to:                   xargs rm -rf           DANGEROUS HIGH -> READONLY LOW
        options:\n  -delete:            find . -name x -delete DANGEROUS HIGH -> READONLY LOW
    """

    def test_a_blank_top_level_scalar_is_rejected(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nclassification:\n")

        db = load_database()
        with pytest.raises(ValueError, match="git.yaml.*every key must carry a value.*'classification'"):
            db["git"]

    def test_a_blank_subcommand_entry_is_rejected(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nsubcommands:\n  push:\n")

        db = load_database()
        with pytest.raises(ValueError, match="'subcommands.push'"):
            db["git"]

    def test_a_blank_option_entry_is_rejected(self, user_config_dir: Path) -> None:
        (user_config_dir / "find.yaml").write_text("command: find\nextends: builtin\noptions:\n  -delete:\n")

        db = load_database()
        with pytest.raises(ValueError, match="'options.-delete'"):
            db["find"]

    def test_a_blank_delegates_to_is_rejected(self, user_config_dir: Path) -> None:
        (user_config_dir / "xargs.yaml").write_text("command: xargs\nextends: builtin\ndelegates_to:\n")

        db = load_database()
        with pytest.raises(ValueError, match="'delegates_to'"):
            db["xargs"]

    def test_a_blank_container_is_rejected(self, user_config_dir: Path) -> None:
        """A bare `subcommands:` would have erased every subcommand the bundled file declares."""
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nsubcommands:\n")

        db = load_database()
        with pytest.raises(ValueError, match="'subcommands'"):
            db["git"]

    def test_a_blank_key_nested_in_a_subcommand_is_rejected(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  push:\n    classification:\n"
        )

        db = load_database()
        with pytest.raises(ValueError, match="'subcommands.push.classification'"):
            db["git"]

    def test_a_blank_key_nested_in_an_option_is_rejected(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  push:\n    options:\n      --force:\n        overrides:\n"
        )

        db = load_database()
        with pytest.raises(ValueError, match="'subcommands.push.options.--force.overrides'"):
            db["git"]

    def test_every_blank_key_is_named_at_once(self, user_config_dir: Path) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nclassification:\nrisk:\nsubcommands:\n  push:\n"
        )

        db = load_database()
        with pytest.raises(ValueError) as excinfo:
            db["git"]
        for path in ("'classification'", "'risk'", "'subcommands.push'"):
            assert path in str(excinfo.value)

    def test_a_key_that_is_both_misspelled_and_blank_reports_the_misspelling(self, user_config_dir: Path) -> None:
        """Otherwise the author fills in a value and only then learns the key was wrong."""
        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nclasification:\n")

        db = load_database()
        with pytest.raises(ValueError, match="unknown field.*clasification"):
            db["git"]

    def test_a_blank_delegates_to_is_not_answered_by_writing_an_empty_one(self, user_config_dir: Path) -> None:
        """The remedy the blank-value message offers must not be a second way into the hole.

        `{}` is the right answer for a subcommand or option entry. For `delegates_to` it is
        not, because an empty block parses as "does not delegate" -- so it is refused too,
        and the message says to omit the key.
        """
        (user_config_dir / "xargs.yaml").write_text("command: xargs\nextends: builtin\ndelegates_to: {}\n")

        db = load_database()
        with pytest.raises(ValueError, match="delegates_to.*missing required field 'mode'"):
            db["xargs"]

    def test_an_empty_mapping_is_the_no_op_it_looks_like(self, user_config_dir: Path) -> None:
        """`{}` is how an author says "this entry, at its bundled settings"."""
        (user_config_dir / "find.yaml").write_text("command: find\nextends: builtin\noptions: {}\nsubcommands: {}\n")

        find = load_database()["find"]
        assert find.options["-delete"].overrides == Classification.DANGEROUS
        assert find.classification == Classification.READONLY

    def test_an_empty_mapping_for_a_single_entry_keeps_the_bundled_entry(self, user_config_dir: Path) -> None:
        (user_config_dir / "find.yaml").write_text("command: find\nextends: builtin\noptions:\n  -delete: {}\n")

        assert load_database()["find"].options["-delete"].overrides == Classification.DANGEROUS

    def test_a_replacing_file_still_accepts_a_blank_value(self, user_config_dir: Path) -> None:
        """Without `extends` a blank key deletes nothing -- there is no bundled value under it.

        The format has always read `-i:` as "an option with all defaults", so the rule is
        scoped to the files where a blank would overwrite something. No bundled file happens
        to use the spelling, but the format accepts it and files outside this repository may.
        """
        (user_config_dir / "zzdemotool.yaml").write_text(
            "command: zzdemotool\nclassification: READONLY\nstrict: false\noptions:\n  -i:\n"
        )

        tool = load_database()["zzdemotool"]
        assert tool.classification == Classification.READONLY
        assert tool.options["-i"].takes_value is False

    def test_a_blank_key_reaches_the_classifier_as_a_refusal_not_a_downgrade(self, user_config_dir: Path) -> None:
        from bash_classify import classify_expression

        (user_config_dir / "git.yaml").write_text("command: git\nextends: builtin\nclassification:\n")

        with pytest.raises(ValueError, match="every key must carry a value"):
            classify_expression("git zzunknown")


class TestExtendsErrorsNameTheRightThing:
    def test_the_bundled_lookup_is_keyed_on_the_filename_not_the_command_value(self, user_config_dir: Path) -> None:
        """A file named zzmytool.yaml is filed under `zzmytool`, whatever `command:` says."""
        (user_config_dir / "zzmytool.yaml").write_text("command: git\nextends: builtin\n")

        db = load_database()
        with pytest.raises(ValueError, match="no 'zzmytool.yaml'"):
            db["zzmytool"]

    def test_a_file_missing_the_command_key_says_so(self, tmp_path: Path) -> None:
        (tmp_path / "nocommand.yaml").write_text("classification: READONLY\n")

        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="nocommand.yaml.*missing required field 'command'"):
            db["nocommand"]


class TestExtendsStaysLazy:
    """Extending resolves two files for one name; it must still resolve neither until asked."""

    @staticmethod
    def _counting_reader(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
        from bash_classify import database as database_module

        reads: list[Path] = []
        real = database_module._read_command_document

        def counting(yaml_file: Path) -> dict:
            reads.append(yaml_file)
            return real(yaml_file)

        monkeypatch.setattr(database_module, "_read_command_document", counting)
        return reads

    def test_building_the_index_and_the_views_parses_nothing(
        self, user_config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {classification: READONLY}\n"
        )
        reads = self._counting_reader(monkeypatch)

        db = load_database()
        assert len(db) > 0
        assert "git" in db
        assert "zzdemotool" not in db
        assert "git" in list(db)
        assert len(db.keys()) == len(db)
        assert len(db.values()) == len(db)
        assert len(db.items()) == len(db)
        assert list(reversed(db))

        assert reads == []

    def test_an_extending_command_reads_both_files_once_and_then_caches(
        self, user_config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {classification: READONLY}\n"
        )
        reads = self._counting_reader(monkeypatch)

        db = load_database()
        db["git"]
        assert reads == [user_config_dir / "git.yaml", get_default_commands_dir() / "git.yaml"]

        db["git"]
        assert len(reads) == 2

    def test_a_plain_user_file_still_reads_only_its_own_file(
        self, user_config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (user_config_dir / "git.yaml").write_text("command: git\nclassification: READONLY\nstrict: false\n")
        reads = self._counting_reader(monkeypatch)

        load_database()["git"]
        assert reads == [user_config_dir / "git.yaml"]

    def test_reading_one_command_does_not_read_its_neighbours(
        self, user_config_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (user_config_dir / "git.yaml").write_text(
            "command: git\nextends: builtin\nsubcommands:\n  zzdemo: {classification: READONLY}\n"
        )
        (user_config_dir / "zzbroken.yaml").write_text("command: zzbroken\nextends: builtin\n")
        reads = self._counting_reader(monkeypatch)

        db = load_database()
        db["git"]
        assert len(reads) == 2
        with pytest.raises(ValueError, match="nothing to extend"):
            db["zzbroken"]

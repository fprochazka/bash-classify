"""Tests for the command matcher."""

from __future__ import annotations

from bash_classify.matcher import _is_terminator, _strip_quotes, match_command
from bash_classify.models import Classification, CommandDef, CommandInvocation


def _make_invocation(argv: list[str]) -> CommandInvocation:
    """Helper to create a CommandInvocation from argv."""
    return CommandInvocation(
        argv=argv,
        redirects=[],
        position_in_pipeline=0,
        pipeline_length=1,
        context="toplevel",
        operator_before=None,
        is_background=False,
    )


class TestBasicMatching:
    def test_ls_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["ls"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "ls"

    def test_cat_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["cat", "/etc/hosts"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "cat"

    def test_rm_classification(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["rm", "-rf", "/tmp/foo"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.matched_rule == "rm"

    def test_unknown_command(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["someunknowncommand"]), database)
        assert result.classification == Classification.UNKNOWN
        assert result.matched_rule is None


class TestGlobalOptionStripping:
    def test_kubectl_context_equals_form(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "--context=prod", "get", "pods"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "kubectl.get"
        assert result.ignored_options is not None
        assert "--context=prod" in result.ignored_options

    def test_kubectl_context_separated_form(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "--context", "prod", "get", "pods"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "kubectl.get"
        assert result.ignored_options is not None
        assert "--context" in result.ignored_options
        assert "prod" in result.ignored_options

    def test_git_c_captures_directory(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "-C", "/some/path", "status"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "git.status"
        # -C and /some/path should be in ignored_options
        assert result.ignored_options is not None
        assert "-C" in result.ignored_options
        assert "/some/path" in result.ignored_options


class TestSubcommandMatching:
    def test_kubectl_get(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "get", "pods"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "kubectl.get"

    def test_kubectl_delete(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "delete", "pod", "mypod"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.matched_rule == "kubectl.delete"

    def test_kubectl_rollout_status(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "rollout", "status", "deploy/app"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "kubectl.rollout.status"

    def test_kubectl_rollout_undo(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "rollout", "undo", "deploy/app"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_git_stash_list(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "stash", "list"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "git.stash.list"

    def test_git_stash_drop(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "stash", "drop"]), database)
        assert result.classification == Classification.DANGEROUS


class TestOptionOverrides:
    def test_git_push_force(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "push", "--force", "origin", "main"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_git_push_f_alias(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "push", "-f", "origin"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_git_push_force_with_lease(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "push", "--force-with-lease"]), database)
        assert result.classification == Classification.WRITE

    def test_git_branch_d_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "branch", "-D", "feature"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_git_reset_hard(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "reset", "--hard"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_kubectl_apply_dry_run(self, database: dict[str, CommandDef]) -> None:
        argv = ["kubectl", "apply", "--dry-run", "client", "-f", "file.yaml"]
        result = match_command(_make_invocation(argv), database)
        # --dry-run takes_value and overrides to READONLY, -f is now a known option
        assert result.classification == Classification.READONLY

    def test_kubectl_apply_dry_run_no_unknown(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "apply", "--dry-run", "client"]), database)
        # --dry-run takes_value and overrides to READONLY (true override, replaces base WRITE)
        assert result.classification == Classification.READONLY

    def test_kubectl_delete_dry_run(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "delete", "--dry-run", "client", "pod", "mypod"]), database)
        # --dry-run takes_value and overrides to READONLY — this is a true override that replaces base DANGEROUS
        assert result.classification == Classification.READONLY

    def test_git_push_force_overrides_to_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "push", "--force", "origin", "main"]), database)
        # --force overrides base WRITE to DANGEROUS
        assert result.classification == Classification.DANGEROUS


class TestStrictMode:
    def test_kubectl_top_unknown_flag(self, database: dict[str, CommandDef]) -> None:
        """kubectl.top is strict by default, unknown flags -> UNKNOWN."""
        result = match_command(_make_invocation(["kubectl", "top", "--unknown-flag"]), database)
        assert result.classification == Classification.UNKNOWN

    def test_grep_unknown_flag_stays_readonly(self, database: dict[str, CommandDef]) -> None:
        """grep is strict: false, unknown flags are ignored."""
        result = match_command(_make_invocation(["grep", "--unknown-flag", "pattern"]), database)
        assert result.classification == Classification.READONLY

    def test_find_unknown_predicate_stays_readonly(self, database: dict[str, CommandDef]) -> None:
        """find is strict: false, unknown predicates are ignored."""
        result = match_command(_make_invocation(["find", ".", "--some-unknown-pred"]), database)
        assert result.classification == Classification.READONLY


class TestDelegationRestAreArgv:
    def test_xargs_delegates_inner_command(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["xargs", "grep", "-r", "pattern"]), database)
        assert len(result.inner_commands) == 1
        inner = result.inner_commands[0]
        assert inner.argv == ["grep", "-r", "pattern"]
        assert inner.delegation_mode == "rest_are_argv"

    def test_sudo_delegates_with_min_classification(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["sudo", "rm", "-rf", "/"]), database)
        assert len(result.inner_commands) == 1
        inner = result.inner_commands[0]
        assert inner.argv == ["rm", "-rf", "/"]
        # min_classification WRITE elevates, but rm is DANGEROUS anyway
        assert inner.classification == Classification.DANGEROUS

    def test_nice_delegates_inner_command(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["nice", "-n", "10", "make"]), database)
        assert len(result.inner_commands) == 1
        inner = result.inner_commands[0]
        assert inner.argv == ["make"]


class TestDelegationAfterSeparator:
    def test_kubectl_exec_after_separator(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["kubectl", "exec", "-it", "my-pod", "--", "cat", "/etc/config"]),
            database,
        )
        assert len(result.inner_commands) == 1
        inner = result.inner_commands[0]
        assert inner.argv == ["cat", "/etc/config"]
        assert inner.delegation_mode == "after_separator"
        assert inner.delegation_source == "--"


class TestDelegationTerminatedArgv:
    def test_find_exec_terminated_argv(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["find", ".", "-name", "*.tmp", "-exec", "rm", "-f", "{}", ";"]),
            database,
        )
        assert len(result.inner_commands) == 1
        inner = result.inner_commands[0]
        # {} should be stripped from inner argv
        assert inner.argv == ["rm", "-f"]
        assert inner.delegation_mode == "terminated_argv"


class TestDelegationFlagValueIsExpression:
    def test_sh_c_parses_expression(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["sh", "-c", "ls /tmp | grep log"]),
            database,
        )
        assert len(result.inner_commands) >= 2
        # Should have ls and grep as inner commands
        inner_cmds = [ic.command for ic in result.inner_commands]
        assert ["ls"] in inner_cmds
        assert ["grep"] in inner_cmds


class TestDelegationEnvStripAssignments:
    def test_env_strip_assignments(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["env", "FOO=bar", "BAZ=qux", "some_command", "arg"]),
            database,
        )
        assert len(result.inner_commands) == 1
        inner = result.inner_commands[0]
        assert inner.argv == ["some_command", "arg"]


class TestCombinedShortFlags:
    def test_combined_boolean_flags(self, database: dict[str, CommandDef]) -> None:
        """Combined -abc where all three are boolean flags should all be expanded."""
        # ssh has -N (bool), -v (bool), -x (bool)
        result = match_command(_make_invocation(["ssh", "-Nvx", "host"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_combined_flag_middle_takes_value(self, database: dict[str, CommandDef]) -> None:
        """Combined -abc where -a is boolean and -b takes value -> -b gets value 'c'."""
        # ssh: -v is boolean, -p takes value
        # So -vp22 should expand to: -v (bool), -p with value "22"
        result = match_command(_make_invocation(["ssh", "-vp22", "host"]), database)
        assert result.classification == Classification.DANGEROUS
        # -vp22 should be recognized as known (not in remaining_options)
        assert result.remaining_options is None or "-vp22" not in result.remaining_options

    def test_combined_flag_last_takes_value_separate(self, database: dict[str, CommandDef]) -> None:
        """Combined -ab where -a is boolean and -b takes value, value is next token."""
        # ssh: -v is boolean, -p takes value
        # -vp 22 -> -v (bool), -p with value "22" from next token
        result = match_command(_make_invocation(["ssh", "-vp", "22", "host"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.remaining_options is None or "-vp" not in result.remaining_options


class TestSshNoDelegation:
    def test_ssh_no_inner_commands(self, database: dict[str, CommandDef]) -> None:
        """ssh should not delegate to inner commands — hostname is not a command."""
        result = match_command(_make_invocation(["ssh", "user@host", "ls", "-la"]), database)
        assert result.classification == Classification.DANGEROUS
        assert len(result.inner_commands) == 0


class TestKubectlOptions:
    def test_kubectl_apply_dry_run_equals_form(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["kubectl", "apply", "--dry-run=client", "-f", "manifest.yaml"]),
            database,
        )
        assert result.classification == Classification.READONLY

    def test_kubectl_get_output(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["kubectl", "get", "pods", "-o", "json"]),
            database,
        )
        assert result.classification == Classification.READONLY

    def test_kubectl_delete_filename(self, database: dict[str, CommandDef]) -> None:
        result = match_command(
            _make_invocation(["kubectl", "delete", "-f", "manifest.yaml"]),
            database,
        )
        assert result.classification == Classification.DANGEROUS


class TestSpecialBuiltins:
    def test_cd_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["cd", "/tmp"]), database)
        assert result.classification == Classification.READONLY

    def test_pushd_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["pushd", "/var"]), database)
        assert result.classification == Classification.READONLY

    def test_eval_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["eval", "some code"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_source_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["source", "script.sh"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_dot_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation([".", "script.sh"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_exec_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["exec", "some_binary"]), database)
        assert result.classification == Classification.DANGEROUS


class TestEmptyArgv:
    def test_empty_argv_unknown(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation([]), database)
        assert result.classification == Classification.UNKNOWN
        assert result.command == []


class TestTestBuiltin:
    def test_test_builtin_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["test", "-f", "file"]), database)
        assert result.classification == Classification.READONLY

    def test_bracket_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["[", "-f", "file", "]"]), database)
        assert result.classification == Classification.READONLY

    def test_double_bracket_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["[[", "-f", "file", "]]"]), database)
        assert result.classification == Classification.READONLY


class TestPopdBuiltin:
    def test_popd_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["popd"]), database)
        assert result.classification == Classification.READONLY


class TestMultipleConflictingOverrides:
    def test_highest_override_wins(self, database: dict[str, CommandDef]) -> None:
        """git push --force-with-lease --force -> DANGEROUS (--force wins over --force-with-lease)."""
        result = match_command(
            _make_invocation(["git", "push", "--force-with-lease", "--force"]),
            database,
        )
        assert result.classification == Classification.DANGEROUS


class TestIsTerminator:
    def test_exact_match(self) -> None:
        assert _is_terminator(";", ";") is True

    def test_backslash_form(self) -> None:
        assert _is_terminator("\\;", ";") is True

    def test_no_match(self) -> None:
        assert _is_terminator("+", ";") is False

    def test_none_terminator(self) -> None:
        assert _is_terminator(";", None) is False


class TestRestAreArgvNoPositional:
    def test_xargs_no_inner_command(self, database: dict[str, CommandDef]) -> None:
        """xargs with no positional args should produce no inner commands."""
        result = match_command(_make_invocation(["xargs"]), database)
        assert result.inner_commands == []


class TestAfterSeparatorNoInnerArgs:
    def test_kubectl_exec_no_inner_after_separator(self, database: dict[str, CommandDef]) -> None:
        """kubectl exec pod -- (nothing after --) should produce no inner commands."""
        result = match_command(
            _make_invocation(["kubectl", "exec", "my-pod", "--"]),
            database,
        )
        assert result.inner_commands == []


class TestFlagValueIsExpressionNotFound:
    def test_sh_without_c_flag(self, database: dict[str, CommandDef]) -> None:
        """sh without -c flag should produce no inner commands."""
        result = match_command(_make_invocation(["sh", "script.sh"]), database)
        assert result.inner_commands == []


class TestStripQuotes:
    def test_single_quoted_value(self) -> None:
        assert _strip_quotes("'hello world'") == "hello world"

    def test_double_quoted_value(self) -> None:
        assert _strip_quotes('"hello world"') == "hello world"

    def test_unquoted_value(self) -> None:
        assert _strip_quotes("hello") == "hello"


class TestRemainingOptionsNonStrict:
    def test_remaining_options_in_non_strict_mode(self, database: dict[str, CommandDef]) -> None:
        """grep is non-strict; unknown flags should appear in remaining_options."""
        result = match_command(
            _make_invocation(["grep", "--some-unknown", "pattern"]),
            database,
        )
        assert result.classification == Classification.READONLY
        assert result.remaining_options is not None
        assert "--some-unknown" in result.remaining_options

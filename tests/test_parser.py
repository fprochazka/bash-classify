"""Tests for the bash expression parser."""

from __future__ import annotations

from bash_classify.parser import parse_expression


class TestSimpleCommands:
    def test_simple_command(self) -> None:
        result, _ = parse_expression("ls")
        assert len(result) == 1
        assert result[0].argv == ["ls"]
        assert result[0].context == "toplevel"
        assert result[0].operator_before is None
        assert result[0].position_in_pipeline == 0
        assert result[0].pipeline_length == 1
        assert result[0].is_background is False

    def test_command_with_args(self) -> None:
        result, _ = parse_expression("ls -la /tmp")
        assert len(result) == 1
        assert result[0].argv == ["ls", "-la", "/tmp"]

    def test_command_with_long_options(self) -> None:
        result, _ = parse_expression("grep --recursive --ignore-case pattern .")
        assert len(result) == 1
        assert result[0].argv == ["grep", "--recursive", "--ignore-case", "pattern", "."]


class TestPipelines:
    def test_simple_pipeline(self) -> None:
        result, _ = parse_expression("cat file | grep pattern | wc -l")
        # Should have 3 pipeline commands + no nested substitutions
        pipeline_cmds = [r for r in result if r.context == "toplevel"]
        assert len(pipeline_cmds) == 3

        assert pipeline_cmds[0].argv == ["cat", "file"]
        assert pipeline_cmds[0].position_in_pipeline == 0
        assert pipeline_cmds[0].pipeline_length == 3

        assert pipeline_cmds[1].argv == ["grep", "pattern"]
        assert pipeline_cmds[1].position_in_pipeline == 1
        assert pipeline_cmds[1].pipeline_length == 3

        assert pipeline_cmds[2].argv == ["wc", "-l"]
        assert pipeline_cmds[2].position_in_pipeline == 2
        assert pipeline_cmds[2].pipeline_length == 3

    def test_two_command_pipeline(self) -> None:
        result, _ = parse_expression("ps aux | grep python")
        pipeline_cmds = [r for r in result if r.context == "toplevel"]
        assert len(pipeline_cmds) == 2
        assert pipeline_cmds[0].pipeline_length == 2
        assert pipeline_cmds[1].pipeline_length == 2


class TestLogicalOperators:
    def test_logical_and(self) -> None:
        result, _ = parse_expression("make && make install")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 2
        assert toplevel[0].argv == ["make"]
        assert toplevel[0].operator_before is None
        assert toplevel[1].argv == ["make", "install"]
        assert toplevel[1].operator_before == "&&"

    def test_logical_or(self) -> None:
        result, _ = parse_expression("cmd1 || cmd2")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 2
        assert toplevel[0].operator_before is None
        assert toplevel[1].operator_before == "||"

    def test_chained_operators(self) -> None:
        result, _ = parse_expression("a && b || c")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 3
        assert toplevel[0].operator_before is None
        assert toplevel[1].operator_before == "&&"
        assert toplevel[2].operator_before == "||"


class TestSemicolons:
    def test_semicolons(self) -> None:
        result, _ = parse_expression("echo a; echo b; echo c")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 3
        assert toplevel[0].argv == ["echo", "a"]
        assert toplevel[0].operator_before is None
        assert toplevel[1].argv == ["echo", "b"]
        assert toplevel[1].operator_before == ";"
        assert toplevel[2].argv == ["echo", "c"]
        assert toplevel[2].operator_before == ";"


class TestCommandSubstitution:
    def test_command_substitution(self) -> None:
        result, _ = parse_expression("echo $(date)")
        # Should have the outer echo and the inner date
        outer = [r for r in result if r.context == "toplevel"]
        inner = [r for r in result if r.context == "command_substitution"]
        assert len(outer) == 1
        assert outer[0].argv == ["echo", "$(date)"]
        assert len(inner) == 1
        assert inner[0].argv == ["date"]

    def test_nested_command_substitution_in_pipeline(self) -> None:
        result, _ = parse_expression("echo $(cat file | wc -l)")
        inner = [r for r in result if r.context == "command_substitution"]
        assert len(inner) == 2
        assert inner[0].argv == ["cat", "file"]
        assert inner[1].argv == ["wc", "-l"]


class TestProcessSubstitution:
    def test_process_substitution(self) -> None:
        result, _ = parse_expression("diff <(ls dir1) <(ls dir2)")
        outer = [r for r in result if r.context == "toplevel"]
        inner = [r for r in result if r.context == "process_substitution"]
        assert len(outer) == 1
        assert outer[0].argv == ["diff", "<(ls dir1)", "<(ls dir2)"]
        assert len(inner) == 2
        assert inner[0].argv == ["ls", "dir1"]
        assert inner[1].argv == ["ls", "dir2"]


class TestSubshell:
    def test_subshell(self) -> None:
        result, _ = parse_expression("(cd /tmp && ls)")
        subshell_cmds = [r for r in result if r.context == "subshell"]
        assert len(subshell_cmds) == 2
        assert subshell_cmds[0].argv == ["cd", "/tmp"]
        assert subshell_cmds[0].operator_before is None
        assert subshell_cmds[1].argv == ["ls"]
        assert subshell_cmds[1].operator_before == "&&"


class TestRedirects:
    def test_output_redirect(self) -> None:
        result, _ = parse_expression("echo hello > output.txt")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert toplevel[0].argv == ["echo", "hello"]
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == ">"
        assert toplevel[0].redirects[0].target == "output.txt"

    def test_stderr_redirect(self) -> None:
        result, _ = parse_expression("cmd 2>/dev/null")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "2>"
        assert toplevel[0].redirects[0].target == "/dev/null"

    def test_append_redirect(self) -> None:
        result, _ = parse_expression("cmd >> file.log")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == ">>"
        assert toplevel[0].redirects[0].target == "file.log"

    def test_input_redirect(self) -> None:
        result, _ = parse_expression("cmd < input.txt")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "<"
        assert toplevel[0].redirects[0].target == "input.txt"

    def test_redirect_affects_classification(self) -> None:
        result, _ = parse_expression("echo hello > output.txt")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert toplevel[0].redirects[0].affects_classification is True

    def test_devnull_redirect_no_affect(self) -> None:
        result, _ = parse_expression("cmd > /dev/null")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert toplevel[0].redirects[0].affects_classification is False


class TestVariableAssignment:
    def test_variable_assignment_prefix(self) -> None:
        result, _ = parse_expression("FOO=bar baz")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert toplevel[0].argv == ["baz"]

    def test_multiple_assignments(self) -> None:
        result, _ = parse_expression("FOO=bar BAZ=qux cmd arg1")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert toplevel[0].argv == ["cmd", "arg1"]

    def test_bare_assignment_no_command(self) -> None:
        # A bare assignment like `FOO=bar` with no command produces no CommandInvocation
        result, _ = parse_expression("FOO=bar")
        assert len(result) == 0


class TestBackground:
    def test_background(self) -> None:
        result, _ = parse_expression("sleep 10 &")
        assert len(result) == 1
        assert result[0].argv == ["sleep", "10"]
        assert result[0].is_background is True

    def test_background_in_list(self) -> None:
        result, _ = parse_expression("cmd1 & cmd2")
        assert len(result) == 2
        assert result[0].is_background is True
        assert result[1].is_background is False


class TestComplex:
    def test_complex_expression(self) -> None:
        result, _ = parse_expression("git status && (cd src && make) | tee log.txt")
        # This should produce:
        # - git status (toplevel, operator_before=None)
        # - cd src (subshell)
        # - make (subshell)
        # - tee log.txt (toplevel, in pipeline)
        toplevel = [r for r in result if r.context == "toplevel"]
        subshell = [r for r in result if r.context == "subshell"]

        # git status should be there
        git_status = [r for r in toplevel if r.argv[0] == "git"]
        assert len(git_status) == 1
        assert git_status[0].argv == ["git", "status"]

        # subshell commands
        assert len(subshell) == 2
        assert subshell[0].argv == ["cd", "src"]
        assert subshell[1].argv == ["make"]

        # tee should be in the pipeline
        tee = [r for r in toplevel if r.argv[0] == "tee"]
        assert len(tee) == 1
        assert tee[0].argv == ["tee", "log.txt"]


class TestHeredoc:
    def test_heredoc(self) -> None:
        expression = "cat <<EOF\nhello\nworld\nEOF"
        result, _ = parse_expression(expression)
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert toplevel[0].argv == ["cat"]
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "<<"
        assert toplevel[0].redirects[0].target == "EOF"

    def test_heredoc_content_not_parsed_as_commands(self) -> None:
        """Heredoc content should NOT be parsed as separate commands."""
        expression = "cat <<EOF\nls -la\nrm -rf /\nEOF"
        result, _ = parse_expression(expression)
        # Only the cat command should be extracted, not ls or rm from heredoc body
        assert len(result) == 1
        assert result[0].argv == ["cat"]


class TestEdgeCases:
    def test_empty_expression(self) -> None:
        result, _ = parse_expression("")
        assert result == []

    def test_comment_only(self) -> None:
        result, _ = parse_expression("# this is a comment")
        assert result == []

    def test_quoted_string_arg(self) -> None:
        result, _ = parse_expression('echo "hello world"')
        assert len(result) == 1
        assert result[0].argv == ["echo", "hello world"]

    def test_single_quoted_string_arg(self) -> None:
        result, _ = parse_expression("echo 'hello world'")
        assert len(result) == 1
        assert result[0].argv == ["echo", "hello world"]


class TestBacktickCommandSubstitution:
    def test_backtick_command_substitution(self) -> None:
        result, _ = parse_expression("echo `date`")
        outer = [r for r in result if r.context == "toplevel"]
        inner = [r for r in result if r.context == "command_substitution"]
        assert len(outer) == 1
        assert len(inner) == 1
        assert inner[0].argv == ["date"]
        assert inner[0].context == "command_substitution"


class TestNegatedCommand:
    def test_negated_command(self) -> None:
        result, _ = parse_expression("! grep pattern file")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert toplevel[0].argv == ["grep", "pattern", "file"]


class TestAnsiCQuotedString:
    def test_dollar_single_quoted_string(self) -> None:
        result, _ = parse_expression("echo $'hello'")
        assert len(result) == 1
        assert result[0].argv == ["echo", "hello"]


class TestMultipleRedirects:
    def test_multiple_redirects(self) -> None:
        result, _ = parse_expression("cmd > out.txt 2> err.txt")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 2


class TestConcatenation:
    def test_concatenation(self) -> None:
        result, _ = parse_expression('echo foo"bar"baz')
        assert len(result) == 1
        # concatenation of word + string + word should produce a single argv entry
        assert result[0].argv == ["echo", "foobarbaz"]


class TestTestCommand:
    def test_single_bracket_test(self) -> None:
        result, _ = parse_expression("[ -f file ]")
        assert len(result) == 1
        assert result[0].argv[0] == "["

    def test_double_bracket_test(self) -> None:
        result, _ = parse_expression("[[ -f file ]]")
        assert len(result) == 1
        assert result[0].argv[0] == "[["

    def test_test_command_in_pipeline(self) -> None:
        result, _ = parse_expression("[ -f file ] && echo exists")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 2
        assert toplevel[0].argv[0] == "["
        assert toplevel[1].argv == ["echo", "exists"]


class TestHerestring:
    def test_herestring_redirect(self) -> None:
        result, _ = parse_expression("cat <<< hello")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert toplevel[0].argv == ["cat"]
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "<<<"
        assert toplevel[0].redirects[0].target == "hello"
        assert toplevel[0].redirects[0].affects_classification is False


class TestRedirectedCompoundStatement:
    def test_for_loop_redirect_not_duplicated(self) -> None:
        """Redirects on compound statements should only be attached to the first command."""
        result, _ = parse_expression("for i in 1 2; do echo $i; done > out.txt")
        # The echo command from inside the loop body
        cmds_with_redirects = [r for r in result if r.redirects]
        # Only one command should have the redirect, not all of them
        assert len(cmds_with_redirects) == 1
        assert cmds_with_redirects[0].redirects[0].operator == ">"
        assert cmds_with_redirects[0].redirects[0].target == "out.txt"


class TestFdToFdRedirects:
    def test_stderr_to_stdout_no_affect(self) -> None:
        """2>&1 is fd-to-fd and should NOT affect classification."""
        result, _ = parse_expression("cmd 2>&1")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].affects_classification is False

    def test_stdout_to_stderr_no_affect(self) -> None:
        """1>&2 is fd-to-fd and should NOT affect classification."""
        result, _ = parse_expression("cmd 1>&2")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].affects_classification is False

    def test_stderr_to_file_affects(self) -> None:
        """2>error.log writes to a file and SHOULD affect classification."""
        result, _ = parse_expression("cmd 2>error.log")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].affects_classification is True


class TestAmpersandRedirects:
    def test_ampersand_redirect_to_file(self) -> None:
        result, _ = parse_expression("cmd &> output.txt")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "&>"
        assert toplevel[0].redirects[0].affects_classification is True

    def test_ampersand_append_redirect_to_file(self) -> None:
        result, _ = parse_expression("cmd &>> output.txt")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "&>>"
        assert toplevel[0].redirects[0].affects_classification is True

    def test_ampersand_redirect_to_devnull(self) -> None:
        result, _ = parse_expression("cmd &> /dev/null")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert toplevel[0].redirects[0].operator == "&>"
        assert toplevel[0].redirects[0].affects_classification is False


class TestProcessSubstitutionAsRedirectTarget:
    def test_output_process_substitution(self) -> None:
        """When > >(tee log.txt) is used, tree-sitter treats the process substitution
        as a redirect target string rather than extracting a nested command.
        Verify the redirect target contains the process substitution text."""
        result, _ = parse_expression("echo hello > >(tee log.txt)")
        toplevel = [r for r in result if r.context == "toplevel"]
        assert len(toplevel) == 1
        assert len(toplevel[0].redirects) == 1
        assert "tee" in toplevel[0].redirects[0].target


class TestParseWarnings:
    def test_syntax_error_produces_warning(self) -> None:
        """Expressions with syntax errors should populate parse_warnings."""
        _, warnings = parse_expression("if then fi else")
        assert len(warnings) >= 1
        assert "syntax error" in warnings[0]

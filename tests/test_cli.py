"""Tests for the CLI entry point."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent

# An empty config dir: no `commands/` subdirectory, so load_database() finds no overrides.
_EMPTY_CONFIG_DIR = tempfile.mkdtemp(prefix="bash-classify-test-config-")


def _run_cli(expression: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run bash-classify CLI with the given argv extras and the expression on stdin.

    Points BASH_CLASSIFY_CONFIG_DIR at an empty directory so a user override in
    ~/.config cannot change what these tests see.
    """
    env = {**os.environ, "BASH_CLASSIFY_CONFIG_DIR": _EMPTY_CONFIG_DIR}
    return subprocess.run(
        [sys.executable, "-m", "bash_classify", *args],
        input=expression,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


class TestCliBasic:
    def test_ls_readonly(self) -> None:
        proc = _run_cli("ls -la")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["classification"] == "READONLY"
        assert "commands" in output
        assert "directories" in output
        assert "expression" in output

    def test_git_push_force_dangerous(self) -> None:
        proc = _run_cli("git push --force")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["classification"] == "DANGEROUS"

    def test_empty_string_exits_with_1(self) -> None:
        proc = _run_cli("")
        assert proc.returncode == 1

    def test_json_output_has_required_fields(self) -> None:
        proc = _run_cli("echo hello")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert "expression" in output
        assert "classification" in output
        assert "commands" in output
        assert "directories" in output


class TestCliDelegation:
    def test_sudo_ls_has_inner_commands(self) -> None:
        proc = _run_cli("sudo ls")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        sudo_cmd = output["commands"][0]
        assert len(sudo_cmd["inner_commands"]) >= 1
        inner = sudo_cmd["inner_commands"][0]
        assert inner["delegation_mode"] == "rest_are_argv"
        assert inner["command"] == ["ls"]


class TestCliRedirect:
    def test_redirect_appears_in_json(self) -> None:
        proc = _run_cli("echo hello > out.txt")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert "redirects" in output
        assert any(r["operator"] == ">" for r in output["redirects"])
        assert output["classification"] == "LOCAL_EFFECTS"


class TestCliClassificationReason:
    def test_classification_reason_in_output(self) -> None:
        proc = _run_cli("ls -la")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        cmd = output["commands"][0]
        assert "classification_reason" in cmd


class TestCliArguments:
    def test_version_prints_package_version(self) -> None:
        from importlib.metadata import version

        proc = _run_cli("", "--version")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert proc.stdout.strip() == f"bash-classify {version('bash-classify')}"

    def test_short_version_flag(self) -> None:
        proc = _run_cli("", "-v")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert proc.stdout.startswith("bash-classify ")

    def test_help_exits_zero(self) -> None:
        proc = _run_cli("", "--help")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert "bash-classify" in proc.stdout

    def test_unknown_argument_exits_2_without_classifying(self) -> None:
        # An older binary silently ignored unknown arguments and classified stdin
        # anyway, which is a fail-open a consumer cannot detect. Now it refuses.
        proc = _run_cli("ls -la", "bogus-arg")
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert "usage: bash-classify" in proc.stderr

    def test_unknown_option_exits_2_without_classifying(self) -> None:
        proc = _run_cli("ls -la", "--no-such-option")
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert "usage: bash-classify" in proc.stderr

    def test_default_mode_output_unchanged(self) -> None:
        proc = _run_cli("ls -la")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["expression"] == "ls -la"
        assert output["classification"] == "READONLY"
        assert output["risk"] == "LOW"
        assert output["commands"][0]["command"] == ["ls"]
        # Pretty-printed with indent 2 and a trailing newline.
        assert proc.stdout.endswith("}\n")
        assert proc.stdout == json.dumps(output, indent=2) + "\n"


class TestCliMatchMode:
    RULES = (
        "rules:\n"
        "  - name: mr-note\n"
        "    command: [glab, mr, note]\n"
        "    except: [[glab, mr, note, list]]\n"
        "  - name: mr-view-comments\n"
        "    command: [glab, mr, view]\n"
        "    any_option: [--comments, -c]\n"
    )

    def _rules_file(self, tmp_path: Path, text: str | None = None) -> Path:
        path = tmp_path / "rules.yaml"
        path.write_text(self.RULES if text is None else text)
        return path

    def test_match_reports_a_match(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        proc = _run_cli("glab mr note 42 -m hi", "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["parse_warnings"] == []
        assert len(output["matches"]) == 1
        match = output["matches"][0]
        assert match["rule"] == "mr-note"
        assert match["command"] == ["glab", "mr", "note"]
        assert match["argv"] == ["glab", "mr", "note", "42", "-m", "hi"]
        assert match["via"] == []

    def test_match_exits_zero_when_nothing_matches(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        proc = _run_cli("glab mr view 42 --output json", "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["matches"] == []
        assert output["parse_warnings"] == []

    def test_both_keys_always_present(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        proc = _run_cli("ls -la", "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert set(json.loads(proc.stdout)) == {"matches", "parse_warnings"}

    def test_parse_warnings_are_reported(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        proc = _run_cli("glab mr note 42 -m hi; if then fi (", "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["parse_warnings"]
        assert len(output["matches"]) == 1

    def test_parse_warnings_from_a_nested_shell_expression(self, tmp_path: Path) -> None:
        """A syntax error inside `bash -c` must reach the caller, matches or not."""
        rules = self._rules_file(tmp_path, "rules:\n  - name: remove\n    command: [rm]\n")
        proc = _run_cli("bash -c 'rm -rf x; for x in;'", "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert [m["rule"] for m in output["matches"]] == ["remove"]
        assert output["parse_warnings"], "a nested syntax error must not be silently swallowed"
        assert "for x in;" in output["parse_warnings"][0]

    def test_via_reports_the_wrapper_chain(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        proc = _run_cli("sudo timeout 5 glab mr note 42 -m hi", "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert json.loads(proc.stdout)["matches"][0]["via"] == ["sudo", "timeout"]

    def test_heredoc_mention_does_not_match(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        expression = (
            "cat > /tmp/work/brief.md <<'EOF'\n"
            "`glab mr view --comments` and `glab mr note` are blocked by a wrapper.\n"
            "EOF\n"
            "echo written"
        )
        proc = _run_cli(expression, "match", "--rules", str(rules))
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["matches"] == []
        assert output["parse_warnings"] == []

    def test_missing_rules_argument_exits_2(self) -> None:
        proc = _run_cli("glab mr note 42", "match")
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert "--rules" in proc.stderr

    def test_nonexistent_rules_file_exits_2_naming_the_path(self, tmp_path: Path) -> None:
        missing = tmp_path / "no-such-rules.yaml"
        proc = _run_cli("glab mr note 42", "match", "--rules", str(missing))
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert str(missing) in proc.stderr

    def test_invalid_rule_exits_2_naming_the_rule(self, tmp_path: Path) -> None:
        rules = self._rules_file(
            tmp_path,
            "rules:\n  - name: broken\n    command: [glab]\n    any_arg_matches: '('\n",
        )
        proc = _run_cli("glab mr note 42", "match", "--rules", str(rules))
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert "broken" in proc.stderr
        assert str(rules) in proc.stderr

    def test_empty_stdin_exits_1(self, tmp_path: Path) -> None:
        rules = self._rules_file(tmp_path)
        proc = _run_cli("", "match", "--rules", str(rules))
        assert proc.returncode == 1

    def test_match_help_exits_zero(self, tmp_path: Path) -> None:
        proc = _run_cli("", "match", "--help")
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert "--rules" in proc.stdout
        assert "exit codes" in proc.stdout


class TestCliSensitivePaths:
    """The acceptance cases, through the real binary.

    A unit test can pass against an implementation that never ships: the hook calls the
    CLI, so the evasion spellings and the false positives are both pinned here.
    """

    @staticmethod
    def _hits(expression: str) -> list[tuple[str, str, str]]:
        proc = _run_cli(expression)
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        return [(h["rule"], h["source"], h["spelling"]) for h in output["sensitive_paths"]]

    def test_reading_a_private_key_is_readonly_and_high_risk(self) -> None:
        proc = _run_cli("cat ~/.ssh/id_rsa")
        output = json.loads(proc.stdout)
        assert output["classification"] == "READONLY"
        assert output["risk"] == "HIGH"
        assert output["sensitive_paths"] == [
            {"token": "~/.ssh/id_rsa", "rule": "ssh", "source": "argv", "spelling": "literal"}
        ]
        assert output["commands"][0]["sensitive_paths"] == output["sensitive_paths"]

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("cat ~/.ssh/id_rsa", ("ssh", "argv", "literal")),
            ("cat ~/.s\\sh/id_rsa", ("ssh", "argv", "posix_escape")),
            ("cat .en\\v", ("dotenv", "argv", "posix_escape")),
            ("cat /etc/sha\\dow", ("shadow", "argv", "posix_escape")),
            ("cat ~/.a\\ws/credentials", ("aws-credentials", "argv", "posix_escape")),
            ("cat ~/.ss?/id_rsa", ("ssh", "argv", "glob")),
            ("cat ~/.s*h/id_rsa", ("ssh", "argv", "glob")),
            ("cat ~/.[s]sh/id_rsa", ("ssh", "argv", "glob")),
            ("cat .en?", ("dotenv", "argv", "glob")),
            ("cat .e*", ("dotenv", "argv", "glob")),
            ("cat ~/.s'sh'/id_rsa", ("ssh", "argv", "literal")),
            ('cat ~/".ssh"/id_rsa', ("ssh", "argv", "literal")),
            ("cat $HOME/.ssh/id_rsa", ("ssh", "argv", "literal")),
            ('cat "$HOME"/.ssh/id_rsa', ("ssh", "argv", "literal")),
            ("cat ${HOME}/.ssh/id_rsa", ("ssh", "argv", "literal")),
            ("cat ~user/.ssh/id_rsa", ("ssh", "argv", "literal")),
            ("cat ~/.[^x]sh/id_rsa", ("ssh", "argv", "glob")),
            ("cat /etc/./shadow", ("shadow", "argv", "literal")),
            ("cat ~/.aws/./credentials", ("aws-credentials", "argv", "literal")),
            ("cat ~/.aws/x/../credentials", ("aws-credentials", "argv", "literal")),
            ("cat < .env", ("dotenv", "redirect_read", "literal")),
            ("echo k >> ~/.ssh/authorized_keys", ("ssh", "redirect_write", "literal")),
            ("echo k >| ~/.ssh/authorized_keys", ("ssh", "redirect_write", "literal")),
            ("echo k 1> ~/.ssh/authorized_keys", ("ssh", "redirect_write", "literal")),
            ("echo k 3> ~/.ssh/authorized_keys", ("ssh", "redirect_write", "literal")),
            ("cat .env.local", ("dotenv", "argv", "literal")),
            ("printenv ANTHROPIC_API_KEY", ("secret-env-var", "argv", "literal")),
            ("env", ("env-dump", "env_dump", "literal")),
            ("printenv", ("env-dump", "env_dump", "literal")),
            ("/usr/bin/printenv", ("env-dump", "env_dump", "literal")),
            ("echo $ANTHROPIC_API_KEY", ("secret-env-var", "argv", "literal")),
        ],
    )
    def test_every_evasion_spelling_is_caught(self, expression: str, expected: tuple[str, str, str]) -> None:
        assert expected in self._hits(expression)

    @pytest.mark.parametrize(
        "expression",
        [
            "sudo cat ~/.ssh/id_rsa",
            "xargs cat ~/.ssh/id_rsa",
            "sh -c 'cat ~/.ssh/id_rsa'",
            'sh -c "sh -c \\"cat ~/.ssh/id_rsa\\""',
            r"find . -name x -exec cat /etc/shadow \;",
            "env cat ~/.ssh/id_rsa",
        ],
    )
    def test_a_hit_at_any_depth_reaches_the_top(self, expression: str) -> None:
        proc = _run_cli(expression)
        output = json.loads(proc.stdout)
        assert output["sensitive_paths"] != []
        assert output["risk"] == "HIGH"

    @pytest.mark.parametrize(
        "expression",
        [
            "ls *",
            "cat .*",
            "git status",
            "grep -rn foo src",
            "env FOO=1 make",
            "printenv PATH",
            "cat .gitignore",
            "ls .github",
            "grep -rn TOKEN src",
            "git log --grep TOKEN",
            "echo API_KEY",
            "cat .env.example",
            "cat .env.template",
            "cat .git/config",
            "cat ~/.gitconfig",
            "cat ~/.aws/config",
            "ls ~/projects",
            "cat .ssh/../notes",
        ],
    )
    def test_the_false_positive_list_stays_clean(self, expression: str) -> None:
        proc = _run_cli(expression)
        output = json.loads(proc.stdout)
        assert output["sensitive_paths"] == []
        assert all(cmd["sensitive_paths"] == [] for cmd in output["commands"])

    def test_the_key_is_always_present(self) -> None:
        """A caller can tell an older binary from a clean verdict only if the key is there."""
        output = json.loads(_run_cli("ls -la").stdout)
        assert output["sensitive_paths"] == []
        assert output["commands"][0]["sensitive_paths"] == []

    def test_a_heredoc_delimiter_is_not_a_path(self) -> None:
        assert self._hits("cat <<.env\nhello\n.env") == []

    def test_the_verdict_does_not_depend_on_the_hooks_own_home(self, tmp_path: Path) -> None:
        """A hook runs under whatever HOME the agent has. The answer must not move with it."""
        env = {**os.environ, "BASH_CLASSIFY_CONFIG_DIR": _EMPTY_CONFIG_DIR, "HOME": "/tmp/.ssh"}
        proc = subprocess.run(
            [sys.executable, "-m", "bash_classify"],
            input="ls ~/projects",
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert output["sensitive_paths"] == []
        assert output["risk"] == "LOW"

    def test_a_user_file_extends_the_denylist(self, tmp_path: Path) -> None:
        (tmp_path / "sensitive-paths.yaml").write_text("rules:\n  - name: acme\n    paths: [.acme/vault]\n")
        env = {**os.environ, "BASH_CLASSIFY_CONFIG_DIR": str(tmp_path)}
        proc = subprocess.run(
            [sys.executable, "-m", "bash_classify"],
            input="cat ~/.acme/vault",
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        output = json.loads(proc.stdout)
        assert [h["rule"] for h in output["sensitive_paths"]] == ["acme"]
        assert output["risk"] == "HIGH"

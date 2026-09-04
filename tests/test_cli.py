"""Tests for the CLI entry point."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def _run_cli(expression: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run bash-classify CLI with the given argv extras and the expression on stdin."""
    return subprocess.run(
        [sys.executable, "-m", "bash_classify", *args],
        input=expression,
        capture_output=True,
        text=True,
        timeout=30,
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

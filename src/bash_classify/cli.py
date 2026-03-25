"""CLI entry point for bash-classify."""

from __future__ import annotations

import json
import sys

from .classifier import classify_expression
from .models import (
    CommandResult,
    ExpressionResult,
    InnerCommandResult,
    Redirect,
)


def _inner_command_to_dict(result: InnerCommandResult) -> dict:
    """Convert an InnerCommandResult to a JSON-serializable dict."""
    d: dict = {
        "delegation_mode": result.delegation_mode,
        "delegation_source": result.delegation_source,
        "command": result.command,
        "argv": result.argv,
        "classification": result.classification.value,
        "matched_rule": result.matched_rule,
    }

    if result.ignored_options:
        d["ignored_options"] = result.ignored_options
    if result.remaining_options:
        d["remaining_options"] = result.remaining_options
    if result.overriding_option is not None:
        d["overriding_option"] = result.overriding_option

    d["inner_commands"] = [_inner_command_to_dict(ic) for ic in result.inner_commands]

    return d


def _command_to_dict(result: CommandResult) -> dict:
    """Convert a CommandResult to a JSON-serializable dict."""
    d: dict = {
        "command": result.command,
        "argv": result.argv,
        "classification": result.classification.value,
        "matched_rule": result.matched_rule,
    }

    if result.ignored_options:
        d["ignored_options"] = result.ignored_options
    if result.remaining_options:
        d["remaining_options"] = result.remaining_options
    if result.classification_reason is not None:
        d["classification_reason"] = result.classification_reason
    if result.overriding_option is not None:
        d["overriding_option"] = result.overriding_option

    d["inner_commands"] = [_inner_command_to_dict(ic) for ic in result.inner_commands]

    return d


def _redirect_to_dict(redirect: Redirect) -> dict:
    """Convert a Redirect to a JSON-serializable dict."""
    return {
        "operator": redirect.operator,
        "target": redirect.target,
        "affects_classification": redirect.affects_classification,
    }


def _result_to_dict(result: ExpressionResult) -> dict:
    """Convert an ExpressionResult to a JSON-serializable dict."""
    d: dict = {
        "expression": result.expression,
        "classification": result.classification.value,
        "directories": result.directories,
        "commands": [_command_to_dict(cmd) for cmd in result.commands],
    }

    if result.redirects:
        d["redirects"] = [_redirect_to_dict(r) for r in result.redirects]

    if result.parse_warnings:
        d["parse_warnings"] = result.parse_warnings

    return d


def main() -> None:
    """Read bash expressions from stdin, classify, and output JSON.

    Exit codes:
        0 - successfully classified
        1 - parse error (invalid bash syntax)
        2 - internal error
    """
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("Usage: bash-classify < command")
        print("       echo 'ls -la' | bash-classify")
        print()
        print("Reads a bash expression from stdin, classifies it, and outputs JSON.")
        print()
        print("Exit codes:")
        print("  0  successfully classified")
        print("  1  empty input")
        print("  2  internal error")
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] in ("-v", "--version"):
        from importlib.metadata import version

        print(f"bash-classify {version('bash-classify')}")
        sys.exit(0)

    try:
        expression = sys.stdin.read().strip()
        if not expression:
            sys.exit(1)

        result = classify_expression(expression)
        output = _result_to_dict(result)
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        print(f"bash-classify: internal error: {e}", file=sys.stderr)
        sys.exit(2)

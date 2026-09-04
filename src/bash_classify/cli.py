"""CLI entry point for bash-classify."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .classifier import classify_expression
from .models import (
    CommandResult,
    ExpressionResult,
    InnerCommandResult,
    Redirect,
)
from .rules import MatchResult, RulesError, load_rules, match_expression


def _inner_command_to_dict(result: InnerCommandResult) -> dict:
    """Convert an InnerCommandResult to a JSON-serializable dict."""
    d: dict = {
        "delegation_mode": result.delegation_mode,
        "delegation_source": result.delegation_source,
        "command": result.command,
        "argv": result.argv,
        "classification": result.classification.value,
        "risk": result.risk.value,
        "matched_rule": result.matched_rule,
        "options": result.options or [],
        "positionals": result.positionals or [],
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
        "risk": result.risk.value,
        "matched_rule": result.matched_rule,
        "options": result.options or [],
        "positionals": result.positionals or [],
    }

    if result.ignored_options:
        d["ignored_options"] = result.ignored_options
    if result.remaining_options:
        d["remaining_options"] = result.remaining_options
    if result.classification_reason is not None:
        d["classification_reason"] = result.classification_reason
    if result.overriding_option is not None:
        d["overriding_option"] = result.overriding_option

    if result.write_paths:
        d["write_paths"] = result.write_paths
    if result.read_paths:
        d["read_paths"] = result.read_paths

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
        "risk": result.risk.value,
        "directories": result.directories,
        "commands": [_command_to_dict(cmd) for cmd in result.commands],
    }

    if result.write_paths:
        d["write_paths"] = result.write_paths
    if result.read_paths:
        d["read_paths"] = result.read_paths

    if result.redirects:
        d["redirects"] = [_redirect_to_dict(r) for r in result.redirects]

    if result.parse_warnings:
        d["parse_warnings"] = result.parse_warnings

    return d


def _match_result_to_dict(result: MatchResult) -> dict:
    """Convert a MatchResult to a JSON-serializable dict."""
    return {
        "matches": [
            {
                "rule": match.rule,
                "command": match.command,
                "argv": match.argv,
                "via": match.via,
            }
            for match in result.matches
        ],
        "parse_warnings": result.parse_warnings,
    }


_EXIT_CODES_HELP = """exit codes:
  0  successfully classified
  1  empty input, or no input on stdin within 5 seconds
  2  bad arguments or internal error
"""

_MATCH_EXIT_CODES_HELP = """exit codes:
  0  ran successfully, whether or not anything matched
  1  empty input, or no input on stdin within 5 seconds
  2  bad arguments, unreadable or invalid rules file, or internal error
"""

_MATCH_DESCRIPTION = """Report which of the command shapes in a rules file the bash expression on stdin
actually invokes, at any depth. Shell text that only mentions a command -- a heredoc
body, an echo string, a # comment, a grep pattern -- is not an invocation and does not
match. Output is JSON with a "matches" list and a "parse_warnings" list; both are always
present. A non-empty "parse_warnings" means the expression could not be fully parsed, so
an empty "matches" proves nothing -- check it before trusting a no-match result.
"""


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    The default mode (no subcommand) reads one bash expression from stdin. Each mode
    registers the function that runs it via ``set_defaults(run=...)``.
    """
    from importlib.metadata import version

    parser = argparse.ArgumentParser(
        prog="bash-classify",
        description="Read a bash expression from stdin, classify it, and output JSON.",
        epilog=_EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"bash-classify {version('bash-classify')}",
    )
    parser.set_defaults(run=_run_default_mode)

    subparsers = parser.add_subparsers(dest="mode", metavar="MODE")
    match_parser = subparsers.add_parser(
        "match",
        help="report which declared command shapes the expression invokes",
        description=_MATCH_DESCRIPTION,
        epilog=_MATCH_EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    match_parser.add_argument(
        "--rules",
        required=True,
        type=Path,
        metavar="PATH",
        help="YAML file declaring the command shapes to look for",
    )
    match_parser.set_defaults(run=_run_match_mode)

    return parser


def _read_expression_from_stdin() -> str:
    """Read one bash expression from stdin, exiting 1 on timeout or empty input."""
    import select

    # Timeout if no data arrives within 5 seconds
    ready, _, _ = select.select([sys.stdin], [], [], 5.0)
    if not ready:
        print("bash-classify: timed out waiting for input on stdin (use --help for usage)", file=sys.stderr)
        sys.exit(1)

    expression = sys.stdin.read().strip()
    if not expression:
        sys.exit(1)
    return expression


def _run_default_mode(args: argparse.Namespace) -> None:
    """Classify the bash expression on stdin and print the JSON result."""
    try:
        expression = _read_expression_from_stdin()
        result = classify_expression(expression)
        output = _result_to_dict(result)
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        print(f"bash-classify: internal error: {e}", file=sys.stderr)
        sys.exit(2)


def _run_match_mode(args: argparse.Namespace) -> None:
    """Match the bash expression on stdin against the rules file and print the result."""
    # Load the rules before touching stdin: a broken rules file is the caller's mistake
    # and must fail the same way whether or not anything is piped in.
    try:
        rules = load_rules(args.rules)
    except RulesError as e:
        print(f"bash-classify: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        expression = _read_expression_from_stdin()
        result = match_expression(expression, rules)
        json.dump(_match_result_to_dict(result), sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.exit(0)
    except Exception as e:
        print(f"bash-classify: internal error: {e}", file=sys.stderr)
        sys.exit(2)


def main() -> None:
    """Parse the command line and run the selected mode.

    Exit codes:
        0 - successfully classified
        1 - empty input, or no input on stdin within 5 seconds
        2 - bad arguments or internal error
    """
    parser = _build_parser()
    args = parser.parse_args()
    args.run(args)

"""Top-level classifier orchestrating parsing, matching, and classification."""

from __future__ import annotations

import os
from collections.abc import Mapping

from .database import load_database
from .matcher import match_command
from .models import (
    Classification,
    CommandDef,
    CommandResult,
    ExpressionResult,
    InnerCommandResult,
    Redirect,
)
from .parser import parse_expression

_SYSTEM_DIRS = (
    "/etc",
    "/lib",
    "/lib64",
    "/usr",
    "/bin",
    "/sbin",
    "/boot",
    "/sys",
    "/proc",
    "/run",
    "/srv",
    "/root",
    "/opt",
    "/var",
    "/dev",
)
_SAFE_PREFIXES = (
    "/tmp",
    "/var/tmp",
    "/home",
    "/dev/null",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd",
    "/dev/tcp",
    "/dev/udp",
)


def _is_system_path(path: str) -> bool:
    """Check if a path is a system directory that should trigger DANGEROUS when written to."""
    if not path.startswith("/"):
        return False
    # Check safe prefixes first (more specific)
    for safe in _SAFE_PREFIXES:
        if path == safe or path.startswith(safe + "/"):
            return False
    # Check system dirs
    return any(path == sysdir or path.startswith(sysdir + "/") for sysdir in _SYSTEM_DIRS)


def classify_expression(
    expression: str,
    database: Mapping[str, CommandDef] | None = None,
) -> ExpressionResult:
    """Classify a bash expression.

    Parses the expression, matches each command against the database,
    and returns a composite classification result.

    Args:
        expression: A bash expression string.
        database: Optional pre-loaded command database. If None, loads the default.

    Returns:
        An ExpressionResult with the overall classification and per-command details.
    """
    # Step 1: Load database if not provided
    if database is None:
        database = load_database()

    # Step 2: Parse the expression
    invocations, parse_warnings = parse_expression(expression)

    # Step 3: Match each command invocation
    command_results: list[CommandResult] = []
    all_redirects: list[Redirect] = []

    for invocation in invocations:
        # Check for variable expansion in command position
        if invocation.argv and invocation.argv[0].startswith("$"):
            result = CommandResult(
                command=[invocation.argv[0]],
                argv=list(invocation.argv),
                classification=Classification.DANGEROUS,
                matched_rule=None,
                inner_commands=[],
                classification_reason="variable expansion in command position",
            )
        else:
            result = match_command(invocation, database)

        # Step 4: Apply redirect classification
        for redirect in invocation.redirects:
            if redirect.affects_classification:
                elevated = Classification.max_severity(result.classification, Classification.LOCAL_EFFECTS)
                if elevated != result.classification:
                    result.classification = elevated
                    result.classification_reason = (
                        f"{result.classification_reason}; elevated by output redirect"
                        if result.classification_reason
                        else "elevated by output redirect"
                    )
            # /dev/tcp and /dev/udp redirects are network access -> DANGEROUS
            if redirect.target.startswith("/dev/tcp/") or redirect.target.startswith("/dev/udp/"):
                elevated = Classification.max_severity(result.classification, Classification.DANGEROUS)
                if elevated != result.classification:
                    result.classification = elevated
                    result.classification_reason = "elevated to DANGEROUS: /dev/tcp or /dev/udp access detected"

        # Step 4b: Check for /dev/tcp and /dev/udp in command arguments
        for arg in invocation.argv:
            if arg.startswith("/dev/tcp/") or arg.startswith("/dev/udp/"):
                elevated = Classification.max_severity(result.classification, Classification.DANGEROUS)
                if elevated != result.classification:
                    result.classification = elevated
                    result.classification_reason = "elevated to DANGEROUS: /dev/tcp or /dev/udp access detected"

        # Step 5: Apply backgrounding
        if invocation.is_background:
            elevated = Classification.max_severity(result.classification, Classification.LOCAL_EFFECTS)
            if elevated != result.classification:
                result.classification = elevated
                result.classification_reason = (
                    f"{result.classification_reason}; elevated by backgrounding"
                    if result.classification_reason
                    else "elevated by backgrounding"
                )

        # Step 6: Elevate to DANGEROUS when writing to system directories
        if result.classification.severity() >= Classification.LOCAL_EFFECTS.severity():
            system_paths_found = []
            # Check argv tokens
            for token in invocation.argv:
                if _is_system_path(token):
                    system_paths_found.append(token)
            # Check redirect targets
            for redirect in invocation.redirects:
                if _is_system_path(redirect.target):
                    system_paths_found.append(redirect.target)

            if system_paths_found and result.classification != Classification.DANGEROUS:
                result.classification = Classification.DANGEROUS
                result.classification_reason = (
                    result.classification_reason or ""
                ) + f"; elevated to DANGEROUS: system path {system_paths_found[0]}"

        command_results.append(result)
        all_redirects.extend(invocation.redirects)

    # Step 7: Collect directories
    directories = _collect_directories(command_results)

    # Step 8: Compute composite classification
    if not command_results and parse_warnings:
        overall = Classification.UNKNOWN
    elif command_results:
        overall = Classification.max_severity(*(r.classification for r in command_results))
    else:
        overall = Classification.READONLY  # empty input

    return ExpressionResult(
        expression=expression,
        classification=overall,
        directories=directories,
        commands=command_results,
        redirects=all_redirects,
        parse_warnings=parse_warnings,
    )


def _extract_directories_from_argv(command: list[str], argv: list[str]) -> list[str]:
    """Extract directories from a command's argv based on well-known command patterns.

    Handles find, ls (first positional arg is a directory) and
    cat/head/tail/less/more (dirname of first positional arg containing /).
    """
    if not command or len(argv) <= 1:
        return []

    binary = command[0]

    # find and ls: first positional (non-option) arg is typically the directory
    if binary in ("find", "ls"):
        for arg in argv[1:]:
            if not arg.startswith("-"):
                return [arg]
        return []

    # File-reading commands: extract dirname from first positional arg containing /
    if binary in ("cat", "head", "tail", "less", "more"):
        for arg in argv[1:]:
            if not arg.startswith("-") and "/" in arg:
                dirname = os.path.dirname(arg)
                if dirname:
                    return [dirname]
                return []
        return []

    return []


def _collect_directories(results: list[CommandResult]) -> list[str]:
    """Collect directories from command results, including inner commands."""
    directories: list[str] = []

    for result in results:
        # Directory builtins: cd, pushd, popd
        if result.command and result.command[0] in ("cd", "pushd") and len(result.argv) > 1:
            directories.append(result.argv[1])

        # Directories captured from global options (e.g., git -C /path)
        if result.directories:
            directories.extend(result.directories)

        # Well-known commands that take directory arguments
        directories.extend(_extract_directories_from_argv(result.command, result.argv))

        # Collect directories from inner commands recursively
        directories.extend(_collect_inner_directories(result.inner_commands))

    return directories


def _collect_inner_directories(results: list[InnerCommandResult]) -> list[str]:
    """Collect directories from inner command results recursively."""
    directories: list[str] = []

    for result in results:
        directories.extend(_extract_directories_from_argv(result.command, result.argv))
        directories.extend(_collect_inner_directories(result.inner_commands))

    return directories

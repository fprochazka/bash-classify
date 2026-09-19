"""Top-level classifier orchestrating parsing, matching, and classification."""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping, Sequence

from .database import load_database
from .matcher import match_command
from .models import (
    Classification,
    CommandDef,
    CommandResult,
    ExpressionResult,
    InnerCommandResult,
    Redirect,
    Risk,
    SensitiveHit,
)
from .parser import parse_expression
from .redirects import is_read_operator, writes_a_file
from .sensitive import SensitiveRule, dedupe_hits, load_sensitive_paths, scan_argv, scan_redirects

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

_DEV_PATHS = ("/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd/")


def _is_temp_path(path: str) -> bool:
    """Check if a path is under a temp directory."""
    return path.startswith("/tmp/") or path == "/tmp" or path.startswith("/var/tmp/") or path == "/var/tmp"


def _is_real_file_path(path: str) -> bool:
    """Check if a redirect target is a real file path (not /dev/null etc)."""
    return all(not (path == dev or path.startswith(dev)) for dev in _DEV_PATHS)


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
    sensitive_rules: Sequence[SensitiveRule] | None = None,
) -> ExpressionResult:
    """Classify a bash expression.

    Parses the expression, matches each command against the database,
    and returns a composite classification result.

    Args:
        expression: A bash expression string.
        database: Optional pre-loaded command database. If None, loads the default.
        sensitive_rules: Optional pre-loaded sensitive-path denylist. If None, loads the
            bundled one plus the user's own.

    Returns:
        An ExpressionResult with the overall classification and per-command details.
    """
    # Step 1: Load database if not provided
    if database is None:
        database = load_database()
    if sensitive_rules is None:
        sensitive_rules = load_sensitive_paths()

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
                risk=Risk.HIGH,
                matched_rule=None,
                inner_commands=[],
                classification_reason="variable expansion in command position",
            )
        else:
            # match_command fills parse_warnings with anything it hits while parsing a
            # nested expression (`bash -c "..."`, `eval "..."`), at any depth.
            result = match_command(invocation, database, parse_warnings)

        # The matcher has already put the output paths named in option values on the
        # result. They stay there alone until the sensitive scan below has run, because the
        # scan reads them to tell an argv write from a mention; the redirect targets join
        # them afterwards.
        argv_write_paths = result.write_paths or []

        # Collect file paths from redirects
        redirect_write_paths: list[str] = []
        read_paths: list[str] = []
        all_write_targets_are_temp = True

        for redirect in invocation.redirects:
            if writes_a_file(redirect.operator, redirect.target) and _is_real_file_path(redirect.target):
                redirect_write_paths.append(redirect.target)
                if not _is_temp_path(redirect.target):
                    all_write_targets_are_temp = False
            elif is_read_operator(redirect.operator) and _is_real_file_path(redirect.target):
                read_paths.append(redirect.target)
            # Heredocs, herestrings and descriptor duplications name no file of their own.

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
                # Only elevate risk if write targets are NOT all temp paths
                if not (redirect_write_paths and all_write_targets_are_temp):
                    result.risk = Risk.max_severity(result.risk, Risk.MEDIUM)
            # /dev/tcp and /dev/udp redirects are network access -> DANGEROUS
            if redirect.target.startswith("/dev/tcp/") or redirect.target.startswith("/dev/udp/"):
                elevated = Classification.max_severity(result.classification, Classification.DANGEROUS)
                if elevated != result.classification:
                    result.classification = elevated
                    result.classification_reason = "elevated to DANGEROUS: /dev/tcp or /dev/udp access detected"
                result.risk = Risk.HIGH

        # Step 4b: Check for /dev/tcp and /dev/udp in command arguments
        for arg in invocation.argv:
            if arg.startswith("/dev/tcp/") or arg.startswith("/dev/udp/"):
                elevated = Classification.max_severity(result.classification, Classification.DANGEROUS)
                if elevated != result.classification:
                    result.classification = elevated
                    result.classification_reason = "elevated to DANGEROUS: /dev/tcp or /dev/udp access detected"
                result.risk = Risk.HIGH

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
            # Elevate risk to at least MEDIUM for backgrounding
            result.risk = Risk.max_severity(result.risk, Risk.MEDIUM)

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
                result.risk = Risk.HIGH

        # Step 6b: Report the tokens that name a credential and floor their risk at HIGH.
        # Deliberately outside the `>= LOCAL_EFFECTS` guard above: `cat ~/.ssh/id_rsa` is
        # READONLY and is exactly the case this exists for.
        _apply_sensitive_paths(result, invocation.redirects, sensitive_rules)

        write_paths = argv_write_paths + redirect_write_paths
        result.write_paths = write_paths if write_paths else None
        result.read_paths = read_paths if read_paths else None

        command_results.append(result)
        all_redirects.extend(invocation.redirects)

    # Step 7: Collect directories
    directories = _collect_directories(command_results)

    # Step 7b: Aggregate write_paths and read_paths
    all_write_paths: list[str] = []
    all_read_paths: list[str] = []
    for cmd_result in command_results:
        if cmd_result.write_paths:
            all_write_paths.extend(cmd_result.write_paths)
        if cmd_result.read_paths:
            all_read_paths.extend(cmd_result.read_paths)
        # A wrapper names no output path of its own, so `sudo curl -o X` reports X only on
        # the inner command. The expression-level list has to reach it, the way the
        # directory list already reaches a `sudo git -C` below a wrapper.
        all_write_paths.extend(_collect_inner_write_paths(cmd_result.inner_commands))

    # Step 8: Compute composite classification and risk
    if not command_results and parse_warnings:
        overall = Classification.UNKNOWN
        overall_risk = Risk.HIGH
    elif command_results:
        overall = Classification.max_severity(*(r.classification for r in command_results))
        overall_risk = Risk.max_severity(*(r.risk for r in command_results))
    else:
        overall = Classification.READONLY  # empty input
        overall_risk = Risk.LOW

    # Step 8b: Collect the hits found at every depth. No separate floor is needed here: each
    # command that carries a hit is already HIGH, and step 8 takes the maximum.
    all_sensitive_paths = dedupe_hits(hit for r in command_results for hit in r.sensitive_paths)

    return ExpressionResult(
        expression=expression,
        classification=overall,
        risk=overall_risk,
        directories=directories,
        write_paths=all_write_paths,
        read_paths=all_read_paths,
        commands=command_results,
        redirects=all_redirects,
        parse_warnings=parse_warnings,
        sensitive_paths=all_sensitive_paths,
    )


def _apply_sensitive_paths(
    result: CommandResult | InnerCommandResult,
    redirects: Sequence[Redirect],
    rules: Sequence[SensitiveRule],
) -> list[SensitiveHit]:
    """Attach the sensitive-path hits of one invocation and of everything below it.

    Every level reports its own argv and its own redirects, plus the hits of its inner
    commands, so a caller that reads only the top of the tree still sees what a wrapper
    hid. A level with any hit gets risk HIGH; classification is left alone.

    Call this before the redirect targets are merged into `write_paths`: the scan reads that
    field to source a hit as `argv_write`, and a redirect target is already sourced as
    `redirect_write` by its own operator.

    A wrapper's own argv holds the inner command's tokens too, so the output paths of
    everything below it count as writes at its level as well. Without that, `sudo curl -o
    ~/.ssh/x` reports the same path twice, as a write from `curl` and as an argument of
    unknown direction from `sudo`.
    """
    output_paths = [*(result.write_paths or []), *_collect_inner_write_paths(result.inner_commands)]
    hits = scan_argv(result.argv, result.command, result.positionals, rules, output_paths=output_paths)
    hits.extend(scan_redirects(redirects, rules))
    for inner in result.inner_commands:
        hits.extend(_apply_sensitive_paths(inner, (), rules))

    result.sensitive_paths = dedupe_hits(hits)
    if result.sensitive_paths:
        result.risk = Risk.HIGH
    return result.sensitive_paths


def _collect_inner_write_paths(results: list[InnerCommandResult]) -> list[str]:
    """Collect the output paths named below a wrapper, recursively."""
    write_paths: list[str] = []
    for result in results:
        if result.write_paths:
            write_paths.extend(result.write_paths)
        write_paths.extend(_collect_inner_write_paths(result.inner_commands))
    return write_paths


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


def iter_invocations(
    result: ExpressionResult,
) -> Iterator[tuple[CommandResult | InnerCommandResult, list[str]]]:
    """Yield every command invocation in the result, depth-first, with its wrapper chain.

    Each pair is ``(invocation, via)``. ``via`` lists the enclosing wrapper commands,
    outermost first, each as its resolved command path joined by spaces (``"sudo"``,
    ``"bash"``, ``"find"``); it is empty for a top-level invocation. Commands inside
    ``$(...)`` are already top-level entries of ``commands``, so they too get an empty
    ``via``.
    """
    for command in result.commands:
        yield command, []
        yield from _iter_inner_invocations(command.inner_commands, [" ".join(command.command)])


def _iter_inner_invocations(
    results: list[InnerCommandResult],
    via: list[str],
) -> Iterator[tuple[InnerCommandResult, list[str]]]:
    """Yield inner invocations depth-first, carrying the wrapper chain that reached them."""
    for result in results:
        yield result, list(via)
        yield from _iter_inner_invocations(result.inner_commands, [*via, " ".join(result.command)])

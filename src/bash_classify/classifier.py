"""Top-level classifier orchestrating parsing, matching, and classification."""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping, Sequence

from .database import load_database

# `_find_flag_value` stays private to `matcher`: it is an implementation detail of how a
# delegating flag is spelled, not part of the package surface, and this is the only other
# reader of it.
from .matcher import _find_flag_value, match_command
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


_EXPRESSION_DELEGATION_MODES = frozenset({"args_are_expression", "flag_value_is_expression"})


def _program_words(argv: Sequence[str], inner_commands: Sequence[InnerCommandResult]) -> list[str]:
    """Collect the program words that appear among this invocation's own argv tokens.

    `argv[0]` is the program being executed, not a path the program operates on, so
    `/usr/bin/git add a.txt` writes nothing into `/usr/bin`. A wrapper carries the words of
    the command it runs in its own argv -- `sudo /usr/bin/git add a.txt` is scanned as
    `['sudo', '/usr/bin/git', 'add', 'a.txt']` -- so those nested words are collected too,
    or only the unwrapped spelling would get the exemption.

    A command reached through a script is deliberately left out: its words are inside the
    script token, not among these tokens, and `_system_paths_in_scripts` scans it against
    its own exemptions. Adding them here would let a word from inside a script be spent on
    an unrelated token of the enclosing command line.
    """
    words = list(argv[:1])
    for inner in inner_commands:
        if inner.delegation_mode in _EXPRESSION_DELEGATION_MODES:
            continue
        if inner.delegation_mode == "terminated_argv" and not _starts_at_its_option(argv, inner):
            continue
        words.extend(_program_words(inner.argv, inner.inner_commands))
    return words


def _starts_at_its_option(argv: Sequence[str], inner: InnerCommandResult) -> bool:
    r"""Tell whether a `find -exec` inner really begins where its option's tokens begin.

    The matcher strips `{}` placeholders before building the inner argv, so in
    `find . -exec {} /usr/bin/git add \;` the inner `argv[0]` is `/usr/bin/git` -- an argument
    handed to whatever file `find` matched, not the program being run. Exempting it would be
    the mistake this whole rule exists to stop, pointed at the wrong token. The inner counts
    as starting at its option only when the option is directly followed by that word.
    """
    if not inner.argv:
        return False
    return any(
        token == inner.delegation_source and argv[index + 1] == inner.argv[0] for index, token in enumerate(argv[:-1])
    )


def _script_tokens(argv: Sequence[str], inner_commands: Sequence[InnerCommandResult]) -> list[str]:
    """Collect the argv tokens that hold a whole script rather than a path.

    `sh -c '/usr/bin/touch /etc/passwd'` hands a command line over as a single token, and a
    scan that compares whole tokens against directory prefixes reads that token as a path
    under `/usr/bin`. The token is source, so it is not scanned as a path; the commands
    parsed out of it are scanned instead, by `_system_paths_in_scripts`.

    Only the token that is the entire script counts. `eval cp a /usr/bin/b` spreads its
    script over several tokens and none of them is it, so every token stays scannable.

    A shell flag written in a cluster (`bash -lc '...'`) is not the flag the database declares,
    so no script is parsed out of it and the token is scanned as a path. For `sh`, `bash` and
    `zsh` that is unobservable -- they are DANGEROUS from their own definitions and the
    elevation never runs -- but a user-declared command with this mode and no DANGEROUS floor
    misses what is inside the script. See SPEC.md.

    Like `_program_words` this stops at the script boundary: a token found by looking inside a
    script does not exist in the enclosing command line, and matching it there by value would
    mask an unrelated token. Each level computes its own.
    """
    tokens: list[str] = []
    for inner in inner_commands:
        if inner.delegation_mode == "flag_value_is_expression":
            value = _find_flag_value(list(argv), inner.delegation_source)
            if value is not None:
                tokens.append(value)
        elif inner.delegation_mode == "args_are_expression" and len(argv) == 2:
            tokens.append(argv[1])
        else:
            tokens.extend(_script_tokens(inner.argv, inner.inner_commands))
    return tokens


def _system_paths_in_argv(argv: Sequence[str], inner_commands: Sequence[InnerCommandResult]) -> list[str]:
    """Find the system paths this invocation names among its own argv tokens.

    Each exempt program word and each script token is consumed once rather than matched by
    value, so a repeat of either still counts: `/usr/bin/git add /usr/bin/git` is a hit, and
    so is the operand in `nohup sh -c /bin/ls /bin/ls`.
    """
    exempt_words = _program_words(argv, inner_commands)
    script_tokens = _script_tokens(argv, inner_commands)
    found: list[str] = []
    for token in argv:
        if token in exempt_words:
            exempt_words.remove(token)
        elif token in script_tokens:
            script_tokens.remove(token)
        elif _is_system_path(token):
            found.append(token)
    return found


def _system_paths_in_scripts(argv: Sequence[str], inner_commands: Sequence[InnerCommandResult]) -> list[str]:
    """Find the system paths named by the commands inside the scripts this invocation runs.

    The elevation is applied to the top-level invocation only, so without this the operands
    inside `sh -c '...'` would be scanned nowhere once the script token itself is skipped.
    Each command parsed out of a script is scanned under *its own* classification, the way a
    top-level command is: in `sh -c 'cat /etc/hosts && touch x'` the `cat` sits below
    `LOCAL_EFFECTS` and its `/etc/hosts` is not a hit, exactly as in the bare spelling.
    """
    found: list[str] = []
    for inner in inner_commands:
        is_script = inner.delegation_mode in _EXPRESSION_DELEGATION_MODES
        if is_script and inner.classification.severity() >= Classification.LOCAL_EFFECTS.severity():
            found.extend(_system_paths_in_argv(inner.argv, inner.inner_commands))
        found.extend(_system_paths_in_scripts(inner.argv, inner.inner_commands))
    return found


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
            # Check argv tokens, then the commands inside any script this one runs
            system_paths_found = _system_paths_in_argv(invocation.argv, result.inner_commands)
            system_paths_found.extend(_system_paths_in_scripts(invocation.argv, result.inner_commands))
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

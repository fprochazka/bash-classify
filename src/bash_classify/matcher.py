"""Command matching and classification against the database."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from .models import (
    Classification,
    CommandDef,
    CommandInvocation,
    CommandResult,
    DelegationConfig,
    DelegationMode,
    InnerCommandResult,
    Risk,
    SubcommandMode,
)

# Shell builtins that are special-cased (not from database)
_BUILTIN_DIRECTORY_COMMANDS = {"cd", "pushd", "popd"}
_BUILTIN_READONLY_COMMANDS = {"[", "[[", "test"}
_BUILTIN_DANGEROUS_COMMANDS = {"eval", "source", ".", "exec"}

# Regex for KEY=VALUE assignments (used by strip_assignments)
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _default_risk(classification: Classification) -> Risk:
    """Return the default risk level for a given classification."""
    if classification in (Classification.DANGEROUS, Classification.UNKNOWN):
        return Risk.HIGH
    if classification == Classification.READONLY:
        return Risk.LOW
    # LOCAL_EFFECTS and EXTERNAL_EFFECTS
    return Risk.MEDIUM


def _clamp_risk(classification: Classification, risk: Risk) -> Risk:
    """Clamp risk to HIGH for DANGEROUS and UNKNOWN classifications."""
    if classification in (Classification.DANGEROUS, Classification.UNKNOWN):
        return Risk.HIGH
    return risk


def match_command(
    invocation: CommandInvocation,
    database: Mapping[str, CommandDef],
) -> CommandResult:
    """Match a parsed CommandInvocation against the command database.

    Performs binary lookup, global option stripping, subcommand matching,
    option classification, and delegation handling.
    """
    argv = invocation.argv
    if not argv:
        return CommandResult(
            command=[],
            argv=[],
            classification=Classification.UNKNOWN,
            risk=Risk.HIGH,
            matched_rule=None,
            inner_commands=[],
        )

    binary = argv[0]

    # Step 0: Handle special builtins
    if binary in _BUILTIN_DIRECTORY_COMMANDS:
        return _handle_directory_builtin(invocation)

    if binary in _BUILTIN_READONLY_COMMANDS:
        return _handle_readonly_builtin(invocation)

    if binary in _BUILTIN_DANGEROUS_COMMANDS:
        return _handle_dangerous_builtin(invocation)

    # Step 1: Binary lookup (try exact match first, then basename as fallback)
    command_def = database.get(binary)
    if command_def is None and (os.sep in binary or "/" in binary):
        basename = os.path.basename(binary)
        command_def = database.get(basename)
        if command_def is not None:
            binary = basename
    if command_def is None:
        return CommandResult(
            command=[binary],
            argv=list(argv),
            classification=Classification.UNKNOWN,
            risk=Risk.HIGH,
            matched_rule=None,
            inner_commands=[],
            classification_reason="command not in database",
        )

    # Step 1b: Resolve alias_of (max depth 1). The user-facing binary stays
    # as typed; only command_def is swapped to the target.
    if command_def.alias_of is not None:
        target_name = command_def.alias_of
        target_def = database.get(target_name)
        if target_def is None:
            raise ValueError(f"{binary} aliases '{target_name}' which is not in the database")
        if target_def.alias_of is not None:
            raise ValueError(f"alias chain too deep: {binary} -> {target_name} -> {target_def.alias_of}")
        command_def = target_def

    remaining = argv[1:]

    # Step 2: Strip global options
    remaining, ignored_options, global_directories, global_overrides, global_risk_overrides = _strip_global_options(
        remaining, command_def
    )

    # Step 3: Subcommand matching
    if command_def.subcommand_mode == SubcommandMode.MATCH_ALL:
        matched_names, matched_defs, remaining = _match_all_subcommands(remaining, command_def)
        matched_def = command_def  # options come from top-level
        command_chain = matched_names
    else:
        matched_def, command_chain, remaining = _match_subcommand(remaining, command_def)
        matched_defs = []  # not used in hierarchical mode

    # Step 4: Option classification
    (
        known_options,
        unknown_options,
        overrides,
        risk_overrides,
        option_directories,
        option_delegations,
        remaining_positional,
    ) = _classify_options(remaining, matched_def)

    # Merge global overrides with subcommand overrides
    all_overrides = global_overrides + overrides
    all_risk_overrides = global_risk_overrides + risk_overrides
    all_directories = global_directories + option_directories

    # Build command path
    full_command = [binary, *command_chain]
    matched_rule = ".".join(full_command) if command_chain else binary

    # Step 5: Determine classification and risk
    base_classification = matched_def.classification
    if base_classification is None:
        base_classification = Classification.READONLY

    # Base risk from command def or default
    base_risk = matched_def.risk if matched_def.risk is not None else _default_risk(base_classification)
    # Track whether risk was explicitly set at command level
    risk_explicitly_set = matched_def.risk is not None

    # Find the highest override — overrides REPLACE the base classification
    classification_reason: str | None = None
    overriding_option: str | None = None

    if all_overrides:
        # When any option has an override, the final classification is the max
        # of all overrides (ignoring the base). This is a true override/replace.
        final_classification = all_overrides[0][1]
        overriding_option = all_overrides[0][0]
        for opt_name, override_class in all_overrides[1:]:
            if override_class.severity() > final_classification.severity():
                final_classification = override_class
                overriding_option = opt_name
        classification_reason = f"overridden by option {overriding_option} to {final_classification.value}"
    else:
        final_classification = base_classification
        classification_reason = f"base classification from rule {matched_rule}"

    # Determine risk from option overrides
    if all_risk_overrides:
        # When any option has a risk override, use max of all risk overrides
        final_risk = all_risk_overrides[0][1]
        for _opt_name, override_risk in all_risk_overrides[1:]:
            if override_risk.severity() > final_risk.severity():
                final_risk = override_risk
    elif all_overrides and not risk_explicitly_set:
        # Classification changed due to option override but no explicit risk override
        # and risk was not explicitly set at command level -> re-derive from new classification
        final_risk = _default_risk(final_classification)
    else:
        final_risk = base_risk

    # Global options that appear after the subcommand (e.g., `kubectl apply --help`)
    # are not caught by _strip_global_options. Check for them here and apply overrides.
    if command_def.global_options:
        for opt in unknown_options[:]:
            opt_key = opt.split("=", 1)[0] if "=" in opt else opt
            global_opt_def = command_def.global_options.get(opt_key)
            if global_opt_def is not None:
                unknown_options.remove(opt)
                if global_opt_def.overrides is not None:
                    all_overrides.append((opt_key, global_opt_def.overrides))
                    # Re-evaluate: override replaces base
                    final_classification = all_overrides[0][1]
                    overriding_option = all_overrides[0][0]
                    for o_name, o_class in all_overrides[1:]:
                        if o_class.severity() > final_classification.severity():
                            final_classification = o_class
                            overriding_option = o_name
                    classification_reason = f"overridden by option {overriding_option} to {final_classification.value}"
                if global_opt_def.risk is not None:
                    all_risk_overrides.append((opt_key, global_opt_def.risk))
                # Re-evaluate risk after global option processing
                if all_risk_overrides:
                    final_risk = all_risk_overrides[0][1]
                    for _o_name, o_risk in all_risk_overrides[1:]:
                        if o_risk.severity() > final_risk.severity():
                            final_risk = o_risk
                elif all_overrides and not risk_explicitly_set:
                    final_risk = _default_risk(final_classification)

    # Step 5b: For match_all, aggregate subcommand classifications/risks
    if command_def.subcommand_mode == SubcommandMode.MATCH_ALL and matched_defs:
        # Compute the aggregate classification/risk from all matched goals
        agg_classification = Classification.READONLY
        agg_risk = Risk.LOW
        for sub_def in matched_defs:
            sub_class = sub_def.classification or Classification.READONLY
            sub_risk = sub_def.risk if sub_def.risk is not None else _default_risk(sub_class)
            agg_classification = Classification.max_severity(agg_classification, sub_class)
            agg_risk = Risk.max_severity(agg_risk, sub_risk)

        # Check if there are unrecognized positional args (non-option tokens)
        has_unrecognized_positional = any(not t.startswith("-") for t in remaining_positional)
        if has_unrecognized_positional:
            # Unrecognized goals: include base classification/risk in aggregation
            agg_risk = Risk.max_severity(agg_risk, base_risk)

        if all_overrides:
            # Option overrides replace base classification; aggregate risk from goals
            # but don't let goals override the option's classification decision
            final_risk = Risk.max_severity(final_risk, agg_risk)
        else:
            # No option overrides: goals determine classification and risk
            final_classification = Classification.max_severity(final_classification, agg_classification)
            final_risk = agg_risk
            classification_reason = f"base classification from rule {matched_rule}"

    # Strict mode: unrecognized options -> UNKNOWN
    if matched_def.strict and unknown_options:
        final_classification = Classification.max_severity(final_classification, Classification.UNKNOWN)
        if final_classification == Classification.UNKNOWN:
            classification_reason = f"unrecognized option {unknown_options[0]} in strict mode"
        final_risk = Risk.HIGH

    # Step 6: Handle delegation
    inner_commands: list[InnerCommandResult] = []
    command_level_inner_count = 0

    # Command-level delegation
    if matched_def.delegates_to is not None:
        command_level_inner = _handle_delegation(
            remaining_positional,
            matched_def.delegates_to,
            database,
            argv,
            matched_def,
        )
        command_level_inner_count = len(command_level_inner)
        inner_commands.extend(command_level_inner)

    # Option-level delegation (e.g., find -exec)
    for opt_name, delegation_config, delegation_tokens in option_delegations:
        inner_results = _handle_option_delegation(opt_name, delegation_config, delegation_tokens, database)
        inner_commands.extend(inner_results)

    # When command-level delegation actually produced inner commands, optionally
    # drop the wrapper's own base classification to `delegated_classification`.
    # This only applies when the current classification came from the command's
    # own base (no option override and no strict-mode escalation) — otherwise
    # we'd be erasing an intentional escalation.
    if (
        matched_def.delegates_to is not None
        and matched_def.delegates_to.delegated_classification is not None
        and command_level_inner_count > 0
        and not all_overrides
        and not (matched_def.strict and unknown_options)
    ):
        final_classification = matched_def.delegates_to.delegated_classification
        if matched_def.delegates_to.delegated_risk is not None:
            final_risk = matched_def.delegates_to.delegated_risk
        else:
            final_risk = _default_risk(final_classification)
        classification_reason = f"delegated to inner via {matched_rule}"

    # Inner command classifications and risks affect the parent
    for inner in inner_commands:
        if inner.classification.severity() > final_classification.severity():
            final_classification = Classification.max_severity(final_classification, inner.classification)
            classification_reason = "elevated by inner command"
        final_risk = Risk.max_severity(final_risk, inner.risk)

    # Clamp risk for DANGEROUS/UNKNOWN classifications
    final_risk = _clamp_risk(final_classification, final_risk)

    # Build remaining_options output
    remaining_opts_output = list(unknown_options)

    return CommandResult(
        command=full_command,
        argv=list(argv),
        classification=final_classification,
        risk=final_risk,
        matched_rule=matched_rule,
        inner_commands=inner_commands,
        ignored_options=ignored_options if ignored_options else None,
        remaining_options=remaining_opts_output if remaining_opts_output else None,
        classification_reason=classification_reason,
        overriding_option=overriding_option,
        directories=all_directories if all_directories else None,
    )


def _handle_directory_builtin(invocation: CommandInvocation) -> CommandResult:
    """Handle cd, pushd, popd builtins."""
    return CommandResult(
        command=[invocation.argv[0]],
        argv=list(invocation.argv),
        classification=Classification.READONLY,
        risk=Risk.LOW,
        matched_rule=None,
        inner_commands=[],
        classification_reason=f"shell builtin (always {Classification.READONLY.value})",
    )


def _handle_readonly_builtin(invocation: CommandInvocation) -> CommandResult:
    """Handle [, [[, test builtins — always READONLY."""
    return CommandResult(
        command=[invocation.argv[0]],
        argv=list(invocation.argv),
        classification=Classification.READONLY,
        risk=Risk.LOW,
        matched_rule=None,
        inner_commands=[],
        classification_reason=f"shell builtin (always {Classification.READONLY.value})",
    )


def _handle_dangerous_builtin(invocation: CommandInvocation) -> CommandResult:
    """Handle eval, source, ., exec builtins."""
    return CommandResult(
        command=[invocation.argv[0]],
        argv=list(invocation.argv),
        classification=Classification.DANGEROUS,
        risk=Risk.HIGH,
        matched_rule=None,
        inner_commands=[],
        classification_reason=f"shell builtin (always {Classification.DANGEROUS.value})",
    )


def _strip_global_options(
    argv: list[str],
    command_def: CommandDef,
) -> tuple[list[str], list[str], list[str], list[tuple[str, Classification]], list[tuple[str, Risk]]]:
    """Strip global options from argv, only before the first subcommand.

    Global options are consumed from the front of argv. Once a non-option token
    is encountered (potential subcommand or positional arg), stripping stops and
    all remaining tokens are passed through.

    Returns (remaining_argv, ignored_options, directories, overrides, risk_overrides).
    """
    if not command_def.global_options:
        return list(argv), [], [], [], []

    remaining: list[str] = []
    ignored: list[str] = []
    directories: list[str] = []
    overrides: list[tuple[str, Classification]] = []
    risk_overrides: list[tuple[str, Risk]] = []
    i = 0

    while i < len(argv):
        token = argv[i]

        # If the token doesn't start with -, it's a subcommand or positional arg.
        # Stop stripping global options; pass the rest through.
        if not token.startswith("-"):
            remaining.extend(argv[i:])
            break

        # Check --key=value form
        if "=" in token:
            key = token.split("=", 1)[0]
            opt_def = command_def.global_options.get(key)
            if opt_def is not None:
                ignored.append(token)
                if opt_def.captures_directory:
                    directories.append(token.split("=", 1)[1])
                if opt_def.overrides is not None:
                    overrides.append((key, opt_def.overrides))
                if opt_def.risk is not None:
                    risk_overrides.append((key, opt_def.risk))
                i += 1
                continue

        # Check exact match
        opt_def = command_def.global_options.get(token)
        if opt_def is not None:
            ignored.append(token)
            if opt_def.overrides is not None:
                overrides.append((token, opt_def.overrides))
            if opt_def.risk is not None:
                risk_overrides.append((token, opt_def.risk))
            if opt_def.takes_value and i + 1 < len(argv):
                i += 1
                ignored.append(argv[i])
                if opt_def.captures_directory:
                    directories.append(argv[i])
            i += 1
            continue

        # Unknown option before subcommand — keep it and continue
        remaining.append(token)
        i += 1

    return remaining, ignored, directories, overrides, risk_overrides


def _match_subcommand(
    argv: list[str],
    command_def: CommandDef,
) -> tuple[CommandDef, list[str], list[str]]:
    """Match subcommand chain from argv.

    Returns (matched_def, command_chain, remaining_argv).
    """
    matched_def = command_def
    command_chain: list[str] = []
    remaining = list(argv)

    while remaining:
        token = remaining[0]

        # Don't try to match options as subcommands
        if token.startswith("-"):
            break

        if token in matched_def.subcommands:
            command_chain.append(token)
            matched_def = matched_def.subcommands[token]
            remaining = remaining[1:]
        else:
            break

    return matched_def, command_chain, remaining


def _match_all_subcommands(
    argv: list[str],
    command_def: CommandDef,
) -> tuple[list[str], list[CommandDef], list[str]]:
    """Match each positional arg independently against the same subcommand dict.

    Used for commands like Maven and Gradle where multiple goals/tasks
    appear as positional args in any order.

    Returns (matched_names, matched_defs, remaining).
    remaining includes both options and unrecognized positional args.
    """
    matched_names: list[str] = []
    matched_defs: list[CommandDef] = []
    remaining: list[str] = []

    for token in argv:
        if token.startswith("-"):
            # Options pass through for _classify_options later
            remaining.append(token)
        elif token in command_def.subcommands:
            matched_names.append(token)
            matched_defs.append(command_def.subcommands[token])
        else:
            # Unrecognized goal — pass through as positional
            remaining.append(token)

    return matched_names, matched_defs, remaining


def _classify_options(
    argv: list[str],
    command_def: CommandDef,
) -> tuple[
    list[str],  # known_options
    list[str],  # unknown_options
    list[tuple[str, Classification]],  # overrides: (option_name, classification)
    list[tuple[str, Risk]],  # risk_overrides: (option_name, risk)
    list[str],  # directories
    list[tuple[str, DelegationConfig, list[str]]],  # option_delegations
    list[str],  # remaining_positional (non-option tokens)
]:
    """Classify options in remaining argv against the matched command's options."""
    known: list[str] = []
    unknown: list[str] = []
    overrides: list[tuple[str, Classification]] = []
    risk_overrides: list[tuple[str, Risk]] = []
    directories: list[str] = []
    delegations: list[tuple[str, DelegationConfig, list[str]]] = []
    positional: list[str] = []
    options = command_def.options

    # For rest_are_argv delegation: once we hit the first positional arg,
    # everything from that point is the inner command (not our options).
    stop_at_first_positional = (
        command_def.delegates_to is not None and command_def.delegates_to.mode == DelegationMode.REST_ARE_ARGV
    )

    i = 0
    end_of_options = False

    while i < len(argv):
        token = argv[i]

        # End of options marker
        if token == "--":
            end_of_options = True
            positional.append(token)
            i += 1
            # Everything after -- is positional
            while i < len(argv):
                positional.append(argv[i])
                i += 1
            break

        if end_of_options or not token.startswith("-"):
            if stop_at_first_positional:
                # Everything from here is the inner command
                positional.extend(argv[i:])
                break
            positional.append(token)
            i += 1
            continue

        # Handle --key=value form
        if token.startswith("--") and "=" in token:
            key = token.split("=", 1)[0]
            value = token.split("=", 1)[1]
            opt_def = options.get(key)
            if opt_def is not None:
                known.append(token)
                if opt_def.overrides is not None:
                    overrides.append((key, opt_def.overrides))
                if opt_def.risk is not None:
                    risk_overrides.append((key, opt_def.risk))
                if opt_def.captures_directory:
                    directories.append(value)
            else:
                unknown.append(token)
            i += 1
            continue

        # Handle long options (--flag or --key value)
        if token.startswith("--"):
            opt_def = options.get(token)
            if opt_def is not None:
                known.append(token)
                if opt_def.overrides is not None:
                    overrides.append((token, opt_def.overrides))
                if opt_def.risk is not None:
                    risk_overrides.append((token, opt_def.risk))
                if opt_def.delegates_to is not None:
                    delegation_tokens = _extract_delegation_tokens(argv, i, opt_def.delegates_to)
                    delegations.append((token, opt_def.delegates_to, delegation_tokens))
                    # Skip past the delegation tokens
                    i = _skip_delegation_tokens(argv, i, opt_def.delegates_to)
                    continue
                if opt_def.takes_value and i + 1 < len(argv):
                    i += 1
                    value = argv[i]
                    known.append(value)
                    if opt_def.captures_directory:
                        directories.append(value)
            else:
                unknown.append(token)
            i += 1
            continue

        # Handle short options (single char like -f, or combined -abc, or -fvalue)
        # First try exact match for the full token (e.g., -it, -delete, -exec)
        opt_def = options.get(token)
        if opt_def is not None:
            known.append(token)
            if opt_def.overrides is not None:
                overrides.append((token, opt_def.overrides))
            if opt_def.risk is not None:
                risk_overrides.append((token, opt_def.risk))
            if opt_def.delegates_to is not None:
                delegation_tokens = _extract_delegation_tokens(argv, i, opt_def.delegates_to)
                delegations.append((token, opt_def.delegates_to, delegation_tokens))
                i = _skip_delegation_tokens(argv, i, opt_def.delegates_to)
                continue
            if opt_def.takes_value and i + 1 < len(argv):
                i += 1
                value = argv[i]
                known.append(value)
                if opt_def.captures_directory:
                    directories.append(value)
            i += 1
            continue

        # Try single-character short option prefix match
        # e.g., -n5 where -n takes a value
        if len(token) >= 2 and token[0] == "-" and token[1] != "-":
            short_flag = f"-{token[1]}"
            opt_def = options.get(short_flag)

            if opt_def is not None and opt_def.takes_value and len(token) > 2:
                # Joined short option with value: -fvalue
                known.append(token)
                value = token[2:]
                if opt_def.overrides is not None:
                    overrides.append((short_flag, opt_def.overrides))
                if opt_def.risk is not None:
                    risk_overrides.append((short_flag, opt_def.risk))
                if opt_def.captures_directory:
                    directories.append(value)
                i += 1
                continue

            if opt_def is not None and not opt_def.takes_value and len(token) > 2:
                # Combined short options: -abc -> -a -b -c
                # If a middle flag takes_value, remaining chars are its joined value.
                all_known = True
                pending_overrides: list[tuple[str, Classification]] = []
                pending_risk_overrides: list[tuple[str, Risk]] = []
                for j in range(1, len(token)):
                    char_flag = f"-{token[j]}"
                    char_def = options.get(char_flag)
                    if char_def is None:
                        all_known = False
                        break
                    if char_def.takes_value:
                        # This flag takes a value: remaining chars are the joined value
                        if char_def.overrides is not None:
                            pending_overrides.append((char_flag, char_def.overrides))
                        if char_def.risk is not None:
                            pending_risk_overrides.append((char_flag, char_def.risk))
                        remaining_chars = token[j + 1 :]
                        if remaining_chars:
                            # Joined value from remaining characters
                            if char_def.captures_directory:
                                directories.append(remaining_chars)
                        else:
                            # Consume next argv token as the value
                            if i + 1 < len(argv):
                                i += 1
                                known.append(argv[i])
                                if char_def.captures_directory:
                                    directories.append(argv[i])
                        break
                    if char_def.overrides is not None:
                        pending_overrides.append((char_flag, char_def.overrides))
                    if char_def.risk is not None:
                        pending_risk_overrides.append((char_flag, char_def.risk))

                if all_known:
                    known.append(token)
                    overrides.extend(pending_overrides)
                    risk_overrides.extend(pending_risk_overrides)
                    i += 1
                    continue

            # Single char short option with separate value
            if opt_def is not None:
                known.append(token)
                if opt_def.overrides is not None:
                    overrides.append((short_flag, opt_def.overrides))
                if opt_def.risk is not None:
                    risk_overrides.append((short_flag, opt_def.risk))
                if opt_def.takes_value and i + 1 < len(argv):
                    i += 1
                    value = argv[i]
                    known.append(value)
                    if opt_def.captures_directory:
                        directories.append(value)
                i += 1
                continue

        # Unknown option
        unknown.append(token)
        i += 1

    return known, unknown, overrides, risk_overrides, directories, delegations, positional


def _is_terminator(token: str, terminator: str | None) -> bool:
    """Check if a token matches a terminator, accounting for backslash-escaped forms.

    Tree-sitter preserves backslash escapes, so \\; in the parsed argv
    should match a terminator of ";".
    """
    if terminator is None:
        return False
    if token == terminator:
        return True
    # Handle backslash-escaped form: \; matches ;
    return token == "\\" + terminator


def _extract_delegation_tokens(
    argv: list[str],
    option_index: int,
    delegation: DelegationConfig,
) -> list[str]:
    """Extract the tokens that form the inner command for option-level delegation."""
    if delegation.mode == DelegationMode.TERMINATED_ARGV:
        # Tokens between the option and the terminator
        tokens: list[str] = []
        i = option_index + 1
        while i < len(argv):
            if _is_terminator(argv[i], delegation.terminator):
                break
            tokens.append(argv[i])
            i += 1
        return tokens
    return []


def _skip_delegation_tokens(
    argv: list[str],
    option_index: int,
    delegation: DelegationConfig,
) -> int:
    """Return the index past the delegation tokens (including terminator)."""
    if delegation.mode == DelegationMode.TERMINATED_ARGV:
        i = option_index + 1
        while i < len(argv):
            if _is_terminator(argv[i], delegation.terminator):
                return i + 1
            i += 1
        return len(argv)
    return option_index + 1


def _handle_delegation(
    remaining_positional: list[str],
    delegation: DelegationConfig,
    database: Mapping[str, CommandDef],
    full_argv: list[str],
    command_def: CommandDef,
) -> list[InnerCommandResult]:
    """Handle command-level delegation (rest_are_argv, after_separator, flag_value_is_expression)."""
    results: list[InnerCommandResult] = []

    if delegation.mode == DelegationMode.REST_ARE_ARGV:
        inner_argv = list(remaining_positional)

        if delegation.strip_assignments:
            # Strip leading KEY=VALUE tokens
            while inner_argv and _ASSIGNMENT_RE.match(inner_argv[0]):
                inner_argv = inner_argv[1:]

        if inner_argv:
            result = _match_inner_command(
                inner_argv,
                database,
                delegation_mode="rest_are_argv",
                delegation_source=command_def.command,
                min_classification=delegation.min_classification,
            )
            results.append(result)

    elif delegation.mode == DelegationMode.AFTER_SEPARATOR:
        separator = delegation.separator or "--"
        # Find separator in remaining positional args
        # But we need to look at full_argv to find separator
        # since positional args include everything after options
        sep_index = None
        for idx, token in enumerate(remaining_positional):
            if token == separator:
                sep_index = idx
                break

        if sep_index is not None:
            inner_argv = remaining_positional[sep_index + 1 :]
            if inner_argv:
                result = _match_inner_command(
                    inner_argv,
                    database,
                    delegation_mode="after_separator",
                    delegation_source=separator,
                    min_classification=delegation.min_classification,
                )
                results.append(result)

    elif delegation.mode == DelegationMode.FLAG_VALUE_IS_EXPRESSION:
        flag = delegation.flag
        if flag is None:
            return results

        # Find the flag value in the original argv
        expression_value = _find_flag_value(full_argv, flag)
        if expression_value is not None:
            # Parse the expression recursively
            from .parser import parse_expression

            inner_invocations, _warnings = parse_expression(expression_value)
            for inv in inner_invocations:
                result = _match_inner_command(
                    inv.argv,
                    database,
                    delegation_mode="flag_value_is_expression",
                    delegation_source=flag,
                    min_classification=delegation.min_classification,
                )
                results.append(result)

    return results


def _handle_option_delegation(
    option_name: str,
    delegation: DelegationConfig,
    delegation_tokens: list[str],
    database: Mapping[str, CommandDef],
) -> list[InnerCommandResult]:
    """Handle option-level delegation (e.g., find -exec)."""
    if delegation.mode == DelegationMode.TERMINATED_ARGV:
        # Strip {} placeholders
        inner_argv = [t for t in delegation_tokens if t != "{}"]
        if inner_argv:
            result = _match_inner_command(
                inner_argv,
                database,
                delegation_mode="terminated_argv",
                delegation_source=option_name,
                min_classification=delegation.min_classification,
            )
            return [result]
    return []


def _match_inner_command(
    argv: list[str],
    database: Mapping[str, CommandDef],
    *,
    delegation_mode: str,
    delegation_source: str,
    min_classification: Classification | None = None,
) -> InnerCommandResult:
    """Recursively match an inner command and return an InnerCommandResult."""
    # Create a synthetic invocation for the inner command
    inner_invocation = CommandInvocation(
        argv=argv,
        redirects=[],
        position_in_pipeline=0,
        pipeline_length=1,
        context="toplevel",
        operator_before=None,
        is_background=False,
    )

    # Recursively match
    inner_result = match_command(inner_invocation, database)

    classification = inner_result.classification
    risk = inner_result.risk
    if min_classification is not None:
        classification = Classification.max_severity(classification, min_classification)
        risk = Risk.max_severity(risk, _default_risk(min_classification))

    # Clamp risk for DANGEROUS/UNKNOWN classifications
    risk = _clamp_risk(classification, risk)

    return InnerCommandResult(
        delegation_mode=delegation_mode,
        delegation_source=delegation_source,
        command=inner_result.command,
        argv=list(argv),
        classification=classification,
        risk=risk,
        matched_rule=inner_result.matched_rule,
        inner_commands=inner_result.inner_commands,
        ignored_options=inner_result.ignored_options,
        remaining_options=inner_result.remaining_options,
        overriding_option=inner_result.overriding_option,
    )


def _find_flag_value(
    argv: list[str],
    flag: str,
) -> str | None:
    """Find the value of a flag in argv."""
    value: str | None = None
    for i, token in enumerate(argv):
        if token == flag and i + 1 < len(argv):
            value = argv[i + 1]
            break
        # Handle --flag=value form
        if token.startswith(flag + "="):
            value = token[len(flag) + 1 :]
            break

    if value is not None:
        value = _strip_quotes(value)

    return value


def _strip_quotes(s: str) -> str:
    """Strip surrounding quotes from a string.

    Tree-sitter preserves shell quotes in parsed tokens, but when we need to
    recursively parse an expression (e.g. the value of sh -c "..."), we must
    remove the outer quotes first.
    """
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    return s

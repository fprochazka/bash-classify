"""Match a bash expression against declared command shapes.

This is the `match` mode: given a small set of rules describing command shapes
(`glab mr note`, `glab api` with a discussions endpoint, ...), report which of them
an expression actually invokes. It answers the question a deny hook really has —
"does this expression run command shape X?" — instead of grepping the raw shell text,
where a heredoc body, an `echo` string or a `#` comment reads the same as a real call.

The module reports; it never decides. The caller owns the policy.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .classifier import classify_expression, iter_invocations
from .models import CommandDef, CommandResult, InnerCommandResult

_RULE_KEYS = frozenset({"name", "command", "except", "any_option", "any_arg_matches"})


class RulesError(ValueError):
    """A rules file is missing, unreadable, or does not describe valid rules."""


@dataclass
class Rule:
    """One command shape to look for.

    Every condition that is given must hold (AND). Rules are independent of each other
    (OR), and one invocation may match several rules.
    """

    name: str
    command: list[str]
    except_: list[list[str]] = field(default_factory=list)
    any_option: list[str] = field(default_factory=list)
    any_arg_matches: re.Pattern[str] | None = None


@dataclass
class Match:
    """One invocation that matched one rule."""

    rule: str
    command: list[str]
    argv: list[str]
    via: list[str]


@dataclass
class MatchResult:
    """Every match found in one expression, plus the parser's own warnings.

    `parse_warnings` is always present, even when empty: a non-empty list means the
    expression could not be fully parsed, so the absence of a match proves nothing and
    the caller has to decide whether to fall back.
    """

    matches: list[Match]
    parse_warnings: list[str]


def load_rules(path: str | Path) -> list[Rule]:
    """Load and validate a rules file.

    Raises:
        RulesError: the file is missing or unreadable, or its contents are not a valid
            rules document. The message always names the file and, where the problem is
            in one rule, that rule by name or by index.
    """
    try:
        raw_text = Path(path).read_text()
    except OSError as e:
        raise RulesError(f"{path}: cannot read rules file: {e}") from e

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        raise RulesError(f"{path}: not valid YAML: {e}") from e

    if not isinstance(data, dict):
        raise RulesError(f"{path}: top level must be a mapping with a 'rules' key")

    unknown_top = sorted(set(data) - {"rules"})
    if unknown_top:
        raise RulesError(f"{path}: unknown top-level key(s): {', '.join(unknown_top)}")

    if "rules" not in data:
        raise RulesError(f"{path}: missing the 'rules' key")

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RulesError(f"{path}: 'rules' must be a non-empty list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule = _parse_rule(path, index, raw_rule)
        if rule.name in seen:
            raise RulesError(f"{path}: rule '{rule.name}': duplicate rule name")
        seen.add(rule.name)
        rules.append(rule)

    return rules


def _parse_rule(path: str | Path, index: int, raw: object) -> Rule:
    """Validate one rule mapping and turn it into a Rule."""
    where = f"{path}: rule #{index}"
    if not isinstance(raw, dict):
        raise RulesError(f"{where}: must be a mapping")

    # Name the rule as soon as it has a usable name, so every later message points at it.
    name = raw.get("name")
    if isinstance(name, str) and name:
        where = f"{path}: rule '{name}'"

    unknown = sorted(set(raw) - _RULE_KEYS)
    if unknown:
        raise RulesError(f"{where}: unknown key(s): {', '.join(unknown)}")

    if not isinstance(name, str) or not name:
        raise RulesError(f"{where}: 'name' must be a non-empty string")

    command = _parse_command_path(where, "command", raw.get("command"))

    except_paths: list[list[str]] = []
    if "except" in raw:
        raw_except = raw["except"]
        if not isinstance(raw_except, list):
            raise RulesError(f"{where}: 'except' must be a list of command paths")
        for excluded in raw_except:
            except_paths.append(_parse_command_path(where, "except entry", excluded))

    any_option: list[str] = []
    if "any_option" in raw:
        raw_any_option = raw["any_option"]
        if not isinstance(raw_any_option, list) or not raw_any_option:
            raise RulesError(f"{where}: 'any_option' must be a non-empty list of option strings")
        for option in raw_any_option:
            if not isinstance(option, str) or not option.startswith("-"):
                raise RulesError(f"{where}: 'any_option' entries must be strings starting with '-', got {option!r}")
            any_option.append(option)

    any_arg_matches: re.Pattern[str] | None = None
    if "any_arg_matches" in raw:
        raw_pattern = raw["any_arg_matches"]
        if not isinstance(raw_pattern, str) or not raw_pattern:
            raise RulesError(f"{where}: 'any_arg_matches' must be a non-empty string")
        try:
            any_arg_matches = re.compile(raw_pattern)
        except re.error as e:
            raise RulesError(f"{where}: 'any_arg_matches' is not a valid Python regex: {e}") from e

    return Rule(
        name=name,
        command=command,
        except_=except_paths,
        any_option=any_option,
        any_arg_matches=any_arg_matches,
    )


def _parse_command_path(where: str, key: str, raw: object) -> list[str]:
    """Validate a command path: a non-empty list of non-empty strings."""
    if not isinstance(raw, list) or not raw:
        raise RulesError(f"{where}: '{key}' must be a non-empty list of strings")
    for word in raw:
        if not isinstance(word, str) or not word:
            raise RulesError(f"{where}: '{key}' entries must be non-empty strings, got {word!r}")
    return list(raw)


def match_expression(
    expression: str,
    rules: Sequence[Rule],
    database: Mapping[str, CommandDef] | None = None,
) -> MatchResult:
    """Report every invocation in `expression` that matches one of `rules`.

    Every invocation is considered, at any depth: top-level commands and, recursively,
    the inner commands that wrappers such as `sudo`, `timeout`, `xargs`, `bash -c`,
    `find -exec`, `eval` and `exec` delegate to. Commands inside `$(...)` are top-level
    invocations in their own right.
    """
    result = classify_expression(expression, database)

    matches: list[Match] = []
    for invocation, via in iter_invocations(result):
        for rule in rules:
            if _rule_matches(rule, invocation):
                matches.append(
                    Match(
                        rule=rule.name,
                        command=list(invocation.command),
                        argv=list(invocation.argv),
                        via=list(via),
                    )
                )

    return MatchResult(matches=matches, parse_warnings=list(result.parse_warnings))


def _rule_matches(rule: Rule, invocation: CommandResult | InnerCommandResult) -> bool:
    """Check one invocation against one rule. Every given condition must hold."""
    command = invocation.command
    if command[: len(rule.command)] != rule.command:
        return False

    for excluded in rule.except_:
        if command[: len(excluded)] == excluded:
            return False

    if rule.any_option:
        options = invocation.options or []
        if not any(option in options for option in rule.any_option):
            return False

    if rule.any_arg_matches is not None:
        pattern = rule.any_arg_matches
        if not any(pattern.search(token) for token in argument_tokens(invocation)):
            return False

    return True


def argument_tokens(invocation: CommandResult | InnerCommandResult) -> list[str]:
    """Return the tokens a rule's `any_arg_matches` is applied to.

    That is `argv[1:]` with the resolved subcommand words removed once each, in order.
    Option flags, option values and positionals are all included; the binary itself and
    the subcommand words that named the command are not — a rule on `[glab, mr]` must
    not match its own `view` subcommand word.
    """
    pending = list(invocation.command[1:])
    tokens: list[str] = []
    for token in invocation.argv[1:]:
        if pending and token == pending[0]:
            pending.pop(0)
            continue
        tokens.append(token)
    return tokens

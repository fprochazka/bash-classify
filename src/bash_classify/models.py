"""Data models for bash-classify."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Classification(enum.Enum):
    """Classification levels for commands, ordered by severity."""

    READONLY = "READONLY"
    LOCAL_EFFECTS = "LOCAL_EFFECTS"
    EXTERNAL_EFFECTS = "EXTERNAL_EFFECTS"
    DANGEROUS = "DANGEROUS"
    UNKNOWN = "UNKNOWN"

    def severity(self) -> int:
        """Return the severity ordering for this classification.

        DANGEROUS > UNKNOWN > EXTERNAL_EFFECTS > LOCAL_EFFECTS > READONLY
        """
        return _SEVERITY_ORDER[self]

    @classmethod
    def max_severity(cls, *classifications: Classification) -> Classification:
        """Return the classification with the highest severity."""
        if not classifications:
            return cls.READONLY
        return max(classifications, key=lambda c: c.severity())


_SEVERITY_ORDER: dict[Classification, int] = {
    Classification.READONLY: 0,
    Classification.LOCAL_EFFECTS: 1,
    Classification.EXTERNAL_EFFECTS: 2,
    Classification.UNKNOWN: 3,
    Classification.DANGEROUS: 4,
}


class Risk(enum.Enum):
    """Risk levels for commands, ordered by severity."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    def severity(self) -> int:
        """Return the severity ordering for this risk level.

        HIGH > MEDIUM > LOW
        """
        return _RISK_SEVERITY_ORDER[self]

    @classmethod
    def max_severity(cls, *risks: Risk) -> Risk:
        """Return the risk with the highest severity."""
        if not risks:
            return cls.LOW
        return max(risks, key=lambda r: r.severity())


_RISK_SEVERITY_ORDER: dict[Risk, int] = {
    Risk.LOW: 0,
    Risk.MEDIUM: 1,
    Risk.HIGH: 2,
}


class SubcommandMode(enum.Enum):
    """How subcommands are matched against positional arguments."""

    HIERARCHICAL = "hierarchical"
    MATCH_ALL = "match_all"


class DelegationMode(enum.Enum):
    """How a command delegates execution to an inner command."""

    REST_ARE_ARGV = "rest_are_argv"
    AFTER_SEPARATOR = "after_separator"
    TERMINATED_ARGV = "terminated_argv"
    FLAG_VALUE_IS_EXPRESSION = "flag_value_is_expression"


@dataclass
class Redirect:
    """A shell redirect extracted from parsing."""

    operator: str
    target: str
    affects_classification: bool


@dataclass
class CommandInvocation:
    """A single command invocation extracted from the parsed bash AST."""

    argv: list[str]
    redirects: list[Redirect]
    position_in_pipeline: int
    pipeline_length: int
    context: str  # "toplevel" | "subshell" | "command_substitution" | "process_substitution"
    operator_before: str | None
    is_background: bool


@dataclass
class DelegationConfig:
    """Configuration for how a command delegates to an inner command."""

    mode: DelegationMode
    separator: str | None = None
    terminator: str | None = None
    flag: str | None = None
    strip_assignments: bool = False
    skip_leading_positionals: int = 0
    min_classification: Classification | None = None


@dataclass
class OptionDef:
    """Definition of a command option from the database."""

    takes_value: bool = False
    aliases: list[str] = field(default_factory=list)
    overrides: Classification | None = None
    risk: Risk | None = None
    captures_directory: bool = False
    delegates_to: DelegationConfig | None = None


@dataclass
class CommandDef:
    """Definition of a command (or subcommand) from the database."""

    command: str
    alias_of: str | None = None
    classification: Classification | None = None
    risk: Risk | None = None
    global_options: dict[str, OptionDef] = field(default_factory=dict)
    subcommands: dict[str, CommandDef] = field(default_factory=dict)
    options: dict[str, OptionDef] = field(default_factory=dict)
    strict: bool = True
    subcommand_mode: SubcommandMode = SubcommandMode.HIERARCHICAL
    delegates_to: DelegationConfig | None = None


@dataclass
class InnerCommandResult:
    """Result of classifying a delegated inner command."""

    delegation_mode: str
    delegation_source: str
    command: list[str]
    argv: list[str]
    classification: Classification
    risk: Risk
    matched_rule: str | None
    inner_commands: list[InnerCommandResult]
    ignored_options: list[str] | None = None
    remaining_options: list[str] | None = None
    overriding_option: str | None = None


@dataclass
class CommandResult:
    """Result of classifying a single top-level command."""

    command: list[str]
    argv: list[str]
    classification: Classification
    risk: Risk
    matched_rule: str | None
    inner_commands: list[InnerCommandResult]
    ignored_options: list[str] | None = None
    remaining_options: list[str] | None = None
    classification_reason: str | None = None
    overriding_option: str | None = None
    directories: list[str] | None = None
    write_paths: list[str] | None = None
    read_paths: list[str] | None = None


@dataclass
class ExpressionResult:
    """Result of classifying a full bash expression."""

    expression: str
    classification: Classification
    risk: Risk
    directories: list[str]
    write_paths: list[str]
    read_paths: list[str]
    commands: list[CommandResult]
    redirects: list[Redirect]
    parse_warnings: list[str]

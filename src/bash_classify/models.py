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
    ARGS_ARE_EXPRESSION = "args_are_expression"


@dataclass(frozen=True)
class SensitiveHit:
    """One token of an expression that names a credential.

    `source` says where the token came from, and `argv` is deliberately vague: `cat X` reads
    and `tee X` writes, and telling them apart needs per-command knowledge the database does
    not carry. Three sources do know the direction. A redirect knows it because the operator
    says so, and an option the database marks `names_output_path` knows it because the tool
    documents that option as naming a file it writes. The caller owns the policy and gets the
    detail to write it.
    """

    token: str
    """The path as it was written, or the argv token that holds it.

    An option value is reported on its own, so `--output=/home/u/.ssh/x` reports
    `/home/u/.ssh/x`. Every other token is reported whole.
    """

    rule: str
    """The denylist entry that matched, such as `ssh` or `aws-credentials`."""

    source: str
    """Where the token was found.

    `argv_write` is a token the command documents as an output path, such as the value of
    `curl -o`. `argv` is every other argument, of unknown direction. The rest name a
    redirect (`redirect_read`, `redirect_write`) or an environment dump (`env_dump`).
    """

    spelling: str = "literal"
    """Which reading of the token matched: `literal`, `posix_escape`, `windows` or `glob`.

    `literal` for a hit that read no path at all, such as an environment dump.
    """


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
    names_output_path: bool = False
    delegates_to: DelegationConfig | None = None


@dataclass
class CommandDef:
    """Definition of a command (or subcommand) from the database.

    ``command`` is the canonical name. A subcommand may additionally be reachable under
    the names in ``aliases``: the parent's ``subcommands`` map holds the very same
    definition object under each of them, so a matched alias still reports the canonical
    name in the resolved command path.
    """

    command: str
    alias_of: str | None = None
    aliases: list[str] = field(default_factory=list)
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
    """Result of classifying a delegated inner command.

    `write_paths` carries only what the inner command's own argv names as output; an inner
    command has no redirects of its own, because the redirect belongs to the wrapper.
    """

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
    options: list[str] | None = None
    positionals: list[str] | None = None
    write_paths: list[str] | None = None
    sensitive_paths: list[SensitiveHit] = field(default_factory=list)


@dataclass
class CommandResult:
    """Result of classifying a single top-level command.

    `write_paths` holds the paths this command names as output: the target of every output
    redirect, and the value of every option the database marks `names_output_path`. It is
    not the complete set of files the command touches. A destination written as a plain
    positional (`cp a b`, `tee out.txt`) is absent, because telling a read positional from a
    write one needs per-command knowledge the database does not carry.
    """

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
    options: list[str] | None = None
    positionals: list[str] | None = None
    sensitive_paths: list[SensitiveHit] = field(default_factory=list)


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
    sensitive_paths: list[SensitiveHit] = field(default_factory=list)

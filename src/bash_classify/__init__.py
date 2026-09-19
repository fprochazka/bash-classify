"""bash-classify: Classify bash expressions by their side-effect risk level.

`__all__` names every symbol a caller outside the package may rely on: the entry points, and
the types those entry points accept or return. Anything else is internal and may move.
"""

from bash_classify.classifier import classify_expression, iter_invocations
from bash_classify.database import CommandDatabase, load_database
from bash_classify.models import (
    Classification,
    CommandDef,
    CommandResult,
    ExpressionResult,
    InnerCommandResult,
    Redirect,
    Risk,
    SensitiveHit,
)
from bash_classify.redirects import (
    is_descriptor_duplication,
    is_read_operator,
    is_write_operator,
    writes_a_file,
)
from bash_classify.rules import Match, MatchResult, Rule, RulesError, load_rules, match_expression
from bash_classify.sensitive import (
    SensitivePathsError,
    SensitiveRule,
    find_path_hits,
    load_sensitive_paths,
)

__all__ = [
    "classify_expression",
    "iter_invocations",
    "load_database",
    "CommandDatabase",
    "CommandDef",
    "Classification",
    "Risk",
    "ExpressionResult",
    "CommandResult",
    "InnerCommandResult",
    "Redirect",
    "Rule",
    "RulesError",
    "Match",
    "MatchResult",
    "load_rules",
    "match_expression",
    "SensitiveHit",
    "SensitiveRule",
    "SensitivePathsError",
    "load_sensitive_paths",
    "find_path_hits",
    "is_write_operator",
    "is_read_operator",
    "is_descriptor_duplication",
    "writes_a_file",
]

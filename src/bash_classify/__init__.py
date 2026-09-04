"""bash-classify: Classify bash expressions by their side-effect risk level."""

from bash_classify.classifier import classify_expression, iter_invocations
from bash_classify.database import CommandDatabase, load_database
from bash_classify.models import Classification, CommandResult, ExpressionResult, Risk
from bash_classify.rules import Match, MatchResult, Rule, RulesError, load_rules, match_expression

__all__ = [
    "classify_expression",
    "iter_invocations",
    "load_database",
    "CommandDatabase",
    "Classification",
    "Risk",
    "ExpressionResult",
    "CommandResult",
    "Rule",
    "RulesError",
    "Match",
    "MatchResult",
    "load_rules",
    "match_expression",
]

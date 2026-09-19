"""What a redirect operator means, for everything that has to ask.

The parser, the classifier and the sensitive-path scan all need to know whether an operator
opens a file and in which direction. They share one definition here because separate ones
drift apart, and the drift is not visible from any single call site: a form that elevates
the classification but contributes no write path never gets the temp-path risk lowering, so
`1> /tmp/f` comes out riskier than `> /tmp/f` for the same operation.
"""

from __future__ import annotations

import re

# A write is `>` or `>>`, each with the leading file descriptor and the `|` no-clobber
# override that bash allows, so `1>` is `>` and `4>>` is `>>`. `&>` and `&>>` redirect both
# streams. `>&` opens a file too, unless its target is a descriptor number.
_WRITE_OPERATOR = re.compile(r"^(?:[0-9]*|&)(?:>>?\|?|>&)$")

# A read is `<`, again with an optional descriptor. The three shapes left out open no file
# the caller named: a `<<` target is the heredoc delimiter, a `<<<` target is the herestring
# text, and a `<&` target is a descriptor number.
_READ_OPERATOR = re.compile(r"^[0-9]*<$")


def is_write_operator(operator: str) -> bool:
    """Return True when the operator opens its target for writing."""
    return _WRITE_OPERATOR.fullmatch(operator) is not None


def is_read_operator(operator: str) -> bool:
    """Return True when the operator opens its target for reading."""
    return _READ_OPERATOR.fullmatch(operator) is not None


def is_descriptor_duplication(operator: str, target: str) -> bool:
    """Return True for `2>&1` and its kin, where the target is a descriptor, not a path."""
    return ">&" in operator and target.isdigit()


def writes_a_file(operator: str, target: str) -> bool:
    """Return True when the redirect creates or changes the file named as its target.

    Two write operators are left out. `> /dev/null` discards output rather than keeping it,
    and a descriptor duplication points one stream at another that is already open.
    """
    if target == "/dev/null":
        return False
    if is_descriptor_duplication(operator, target):
        return False
    return is_write_operator(operator)

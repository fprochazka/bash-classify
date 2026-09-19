"""What a redirect operator means, for everything that has to ask.

Direction is a property of the operator alone, so the answer belongs to no single caller.
It is kept in one place because separate copies of it drift apart, and the drift is not
visible from any one call site.
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

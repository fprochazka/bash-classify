"""Consumer fixture suites for `match` mode.

Each suite under `tests/fixtures/match/<consumer>/` holds the rules a real deny hook uses
plus two directories of one-expression-per-file shell fixtures, mined from Claude Code
transcripts and sanitized:

- `block/` — a real invocation of a blocked command shape. Must yield at least one match.
- `allow/` — either an adjacent command that is not blocked, or shell text that merely
  *mentions* a blocked command (a heredoc body, an `echo` string, a `#` comment, a
  `git commit -m` message, a `grep` pattern). Must yield no match at all.

Both directions additionally require empty `parse_warnings`: a fixture the parser cannot
read would prove nothing either way.

Two mined shapes are deliberately absent. Both write a script through a heredoc and then
execute it in the same command (`bash /tmp/work/lint.sh`, or `chmod +x` followed by
running the file). Statically they are text mentions — the heredoc body is data and the
executed part is `bash <path>`, whose contents bash-classify never sees — but operationally
they do run the blocked command. They belong in neither directory, so they are left out;
a consumer that cares about them needs a policy answer, not a fixture.

The last test pins the mechanism the whole mode rests on: a heredoc body is dropped by the
parser and never becomes an argument. That holds for a *plain* heredoc
(`cat > file <<'EOF'`). A heredoc inside a command substitution
(`git commit -m "$(cat <<'EOF' ... )"`) is part of the enclosing word, so its text does
reach argv as the value of `-m` — correctly, because that is exactly what the shell hands
to git. The same goes for any quoted argument: `echo "... is blocked"` really does pass
that string to `echo`. Neither is an invocation, which is what the match tests above
assert; a blanket "no rule phrase appears in any argv token" would be false for both.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bash_classify.classifier import classify_expression, iter_invocations
from bash_classify.database import load_database
from bash_classify.models import CommandDef
from bash_classify.rules import load_rules, match_expression

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "match"
COMMANDS_DIR = Path(__file__).parent.parent / "src" / "bash_classify" / "commands"


@pytest.fixture(scope="module")
def db() -> dict[str, CommandDef]:
    return load_database(COMMANDS_DIR)


def _suites() -> list[Path]:
    return sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())


def _fixtures(kind: str) -> list[Path]:
    return sorted(path for suite in _suites() for path in (suite / kind).glob("*.sh"))


def _fixture_id(path: Path) -> str:
    return f"{path.parent.parent.name}/{path.parent.name}/{path.name}"


def _rules_for(fixture: Path):
    return load_rules(fixture.parent.parent / "rules.yaml")


@pytest.mark.parametrize("fixture", _fixtures("block"), ids=_fixture_id)
def test_block_fixture_matches(fixture: Path, db) -> None:
    result = match_expression(fixture.read_text(), _rules_for(fixture), db)
    assert result.parse_warnings == [], f"{_fixture_id(fixture)}: {result.parse_warnings}"
    assert result.matches, f"{_fixture_id(fixture)}: expected at least one match"


@pytest.mark.parametrize("fixture", _fixtures("allow"), ids=_fixture_id)
def test_allow_fixture_does_not_match(fixture: Path, db) -> None:
    result = match_expression(fixture.read_text(), _rules_for(fixture), db)
    assert result.parse_warnings == [], f"{_fixture_id(fixture)}: {result.parse_warnings}"
    assert result.matches == [], f"{_fixture_id(fixture)}: unexpected match {result.matches}"


def test_every_suite_has_both_directions() -> None:
    suites = _suites()
    assert suites, "no fixture suites found"
    for suite in suites:
        assert (suite / "rules.yaml").is_file(), f"{suite.name}: missing rules.yaml"
        assert list((suite / "block").glob("*.sh")), f"{suite.name}: no block fixtures"
        assert list((suite / "allow").glob("*.sh")), f"{suite.name}: no allow fixtures"


@pytest.mark.parametrize("suite", _suites(), ids=lambda p: p.name)
def test_every_rule_is_exercised_by_a_block_fixture(suite: Path, db) -> None:
    """A rule no fixture reaches is a rule nothing protects."""
    rules = load_rules(suite / "rules.yaml")
    matched: set[str] = set()
    for fixture in sorted((suite / "block").glob("*.sh")):
        for match in match_expression(fixture.read_text(), rules, db).matches:
            matched.add(match.rule)
    unexercised = sorted({rule.name for rule in rules} - matched)
    assert not unexercised, f"{suite.name}: rules with no block fixture: {', '.join(unexercised)}"


# `<<EOF`, `<<'EOF'`, `<<"EOF"` and the `<<-` variant, anywhere on the line: a heredoc may
# be followed by further redirects (`cat <<'EOF' > f`) or a pipeline (`cat <<'PY' | python3`).
_HEREDOC_OPENER = re.compile(
    r"""<<-?\s*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))"""
)


def _plain_heredoc_bodies(text: str) -> list[list[str]]:
    """Return the bodies of heredocs that are redirects rather than command substitutions.

    A heredoc opened inside `$(...)` belongs to the enclosing word and its text really does
    become an argument, so those are skipped: an opener is treated as plain only when no
    unclosed `$(` precedes it on the line.
    """
    lines = text.splitlines()
    bodies: list[list[str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        opener = next(
            (m for m in _HEREDOC_OPENER.finditer(line) if not _inside_substitution(line, m.start())),
            None,
        )
        if opener is not None:
            delimiter = next(group for group in opener.groups() if group)
            i += 1
            body: list[str] = []
            while i < len(lines) and lines[i].strip() != delimiter:
                body.append(lines[i])
                i += 1
            bodies.append(body)
        i += 1
    return bodies


def _inside_substitution(line: str, index: int) -> bool:
    """True when `line[index]` sits inside an unclosed `$(` on that line."""
    depth = 0
    i = 0
    while i < index:
        if line.startswith("$(", i):
            depth += 1
            i += 2
            continue
        if line[i] == ")" and depth:
            depth -= 1
        i += 1
    return depth > 0


def _fixtures_with_plain_heredoc(kind: str) -> list[Path]:
    return [path for path in _fixtures(kind) if any(_plain_heredoc_bodies(path.read_text()))]


@pytest.mark.parametrize("fixture", _fixtures_with_plain_heredoc("allow"), ids=_fixture_id)
def test_plain_heredoc_body_never_reaches_argv(fixture: Path, db) -> None:
    """The body of a heredoc redirect is data: it must not appear in any argv token.

    This is the invariant the original false positive violated. A brief written with
    `cat > file <<'EOF'` was denied because its prose named a blocked command.
    """
    text = fixture.read_text()
    result = classify_expression(text, db)
    tokens = [token for invocation, _via in iter_invocations(result) for token in invocation.argv]
    for body in _plain_heredoc_bodies(text):
        for line in body:
            stripped = line.strip()
            if len(stripped) < 20:
                continue
            for token in tokens:
                assert stripped not in token, (
                    f"{_fixture_id(fixture)}: heredoc body line {stripped!r} reached argv token {token!r}"
                )

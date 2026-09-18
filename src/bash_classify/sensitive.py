"""Report the tokens of an expression that name a credential.

The classifier answers what a command does to the system. It has no opinion on what the
command touches, so `cat ~/.ssh/id_rsa` is READONLY and, until this module runs, LOW. Every
consumer that auto-approves on LOW therefore auto-approves reading a private key.

The split kept here: classification is untouched, because reading a file really is
read-only and that axis describes the scope of side effects. Risk is the axis for "how much
should a human care", so a hit floors it at HIGH. The hits themselves are reported on the
result, so a caller that wants a different policy has the detail to write one.

The verdict depends on the expression alone. Nothing here reads the environment of the
process doing the classifying, so `~` and `$HOME` stay unresolved segments: a hook must give
the same answer whatever `HOME` it happens to run under.

This is a speed bump against an agent being careless, not a control against one being
evaded. Command substitution, a path held in a variable, and any encoding detour all defeat
it; SPEC.md lists what it misses.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import Redirect, SensitiveHit

# Redirects are the only place where direction is known, because the operator says so.
# Both shapes allow the optional leading file descriptor that bash allows, so `1>` is `>`
# and `4>>` is `>>`. A heredoc (`<<`) target is the delimiter word, a herestring (`<<<`)
# target is the text itself, and `<&` names a descriptor, so none of the three is a path.
_WRITE_OPERATOR = re.compile(r"^(?:[0-9]*|&)(?:>>?\|?|>&)$")
_READ_OPERATOR = re.compile(r"^[0-9]*<$")

_GLOB_METACHARACTERS = frozenset("*?[]")

# A glob segment is read backwards, matching the denylisted name against the token as a
# pattern, so `.ss?` catches `.ssh`. Without a floor that rule eats everything, because
# fnmatch(".ssh", "*") is true. Two literal characters is the tightest real evasion, `.e*`,
# and it leaves `*`, `?`, `.*` and `**` alone. So `cat .*` is not reported: a deliberate
# hole, cheaper than the false positives that closing it would cost.
_MIN_GLOB_LITERAL_CHARS = 2

# An argument that names an environment variable holding a secret. Segments are matched
# whole, so MONKEY is not a KEY, while APIKEY and CREDENTIALS still are.
_SECRET_NAME_SEGMENT = re.compile(r"(?:API|SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL)+S?")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*")

_ENVIRONMENT_DUMP_COMMANDS = frozenset({"env", "printenv"})

# A bare `API_KEY` is a variable name to these commands and a search string to everything
# else. Without the restriction `grep -rn TOKEN src` and `git log --grep TOKEN` are hits,
# and a gate that fires on those is a gate people switch off. `$API_KEY` needs no such
# restriction: the `$` says it is a variable wherever it appears.
_VARIABLE_NAME_COMMANDS = frozenset({"env", "printenv", "export", "unset"})

_RULE_KEYS = frozenset({"name", "paths", "except_paths"})


class SensitivePathsError(ValueError):
    """A sensitive-paths file is unreadable, or does not describe valid rules."""


@dataclass(frozen=True)
class SensitiveRule:
    """One named secret, with every path spelling that reaches it.

    Each entry of `paths` is already split into segments. A token hits the rule when any
    one of them appears in it, and no entry of `except_paths` does.
    """

    name: str
    paths: tuple[tuple[str, ...], ...]
    except_paths: tuple[tuple[str, ...], ...] = ()


def get_default_sensitive_paths_file() -> Path:
    """Return the sensitive-paths file bundled with the package."""
    return Path(__file__).parent / "sensitive-paths.yaml"


def get_user_sensitive_paths_file() -> Path:
    """Return the user's sensitive-paths file, whether or not it exists."""
    config_dir = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
    if config_dir:
        return Path(config_dir) / "sensitive-paths.yaml"
    return Path.home() / ".config" / "bash-classify" / "sensitive-paths.yaml"


def load_sensitive_paths(path: str | Path | None = None) -> list[SensitiveRule]:
    """Load the denylist, bundled rules first and the user's own after.

    A user rule that reuses a bundled name replaces that rule, which is how you loosen or
    drop one you do not want. Any other user rule is added.

    Args:
        path: An explicit file to load instead of both defaults. Nothing is merged into it.

    Raises:
        SensitivePathsError: A file is unreadable, or its contents are not valid rules. The
            message names the file and the rule that caused it.
    """
    if path is not None:
        return _merge(_load_file(Path(path)), [])

    builtin = _load_file_cached(get_default_sensitive_paths_file())
    user_file = get_user_sensitive_paths_file()
    if not user_file.is_file():
        return list(builtin)
    return _merge(builtin, _load_file_cached(user_file))


def _merge(base: Sequence[SensitiveRule], extra: Sequence[SensitiveRule]) -> list[SensitiveRule]:
    """Combine two rule lists, keeping the order of `base` and letting `extra` win by name."""
    replacements = {rule.name: rule for rule in extra}
    merged = [replacements.pop(rule.name, rule) for rule in base]
    merged.extend(rule for rule in extra if rule.name in replacements)
    return merged


_FILE_CACHE: dict[tuple[Path, int, int], list[SensitiveRule]] = {}


def _load_file_cached(file: Path) -> list[SensitiveRule]:
    """Load a rules file, reparsing it only after it changes on disk.

    `classify_expression` is called once per command in a hook, so the parse is on the hot
    path; the file is small but the classifier does not otherwise touch the disk per call.
    """
    try:
        stat = file.stat()
    except OSError:
        return _load_file(file)
    key = (file, stat.st_mtime_ns, stat.st_size)
    cached = _FILE_CACHE.get(key)
    if cached is None:
        cached = _load_file(file)
        _FILE_CACHE[key] = cached
    return list(cached)


def _load_file(file: Path) -> list[SensitiveRule]:
    """Read and validate one sensitive-paths file."""
    try:
        raw_text = file.read_text()
    except OSError as e:
        raise SensitivePathsError(f"{file}: cannot read sensitive-paths file: {e}") from e

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        raise SensitivePathsError(f"{file}: not valid YAML: {e}") from e

    if not isinstance(data, dict):
        raise SensitivePathsError(f"{file}: top level must be a mapping with a 'rules' key")

    unknown_top = sorted(set(data) - {"rules"})
    if unknown_top:
        raise SensitivePathsError(f"{file}: unknown top-level key(s): {', '.join(unknown_top)}")

    if "rules" not in data:
        raise SensitivePathsError(f"{file}: missing the 'rules' key")

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise SensitivePathsError(f"{file}: 'rules' must be a non-empty list")

    rules: list[SensitiveRule] = []
    seen: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule = _parse_rule(file, index, raw_rule)
        if rule.name in seen:
            raise SensitivePathsError(f"{file}: rule '{rule.name}': duplicate rule name")
        seen.add(rule.name)
        rules.append(rule)

    return rules


def _parse_rule(file: Path, index: int, raw: object) -> SensitiveRule:
    """Validate one rule mapping and turn it into a SensitiveRule."""
    where = f"{file}: rule #{index}"
    if not isinstance(raw, dict):
        raise SensitivePathsError(f"{where}: must be a mapping")

    # Name the rule as soon as it has a usable name, so every later message points at it.
    name = raw.get("name")
    if isinstance(name, str) and name:
        where = f"{file}: rule '{name}'"

    unknown = sorted(set(raw) - _RULE_KEYS)
    if unknown:
        raise SensitivePathsError(f"{where}: unknown key(s): {', '.join(unknown)}")

    if not isinstance(name, str) or not name:
        raise SensitivePathsError(f"{where}: 'name' must be a non-empty string")

    return SensitiveRule(
        name=name,
        paths=_parse_paths(where, "paths", raw.get("paths"), required=True),
        except_paths=_parse_paths(where, "except_paths", raw.get("except_paths"), required=False),
    )


def _parse_paths(where: str, key: str, raw: object, *, required: bool) -> tuple[tuple[str, ...], ...]:
    """Validate one of the path lists and split each entry into segments."""
    if raw is None and not required:
        return ()
    if not isinstance(raw, list) or not raw:
        raise SensitivePathsError(f"{where}: '{key}' must be a non-empty list of path strings")

    paths: list[tuple[str, ...]] = []
    for raw_path in raw:
        if not isinstance(raw_path, str):
            raise SensitivePathsError(f"{where}: '{key}' entries must be strings, got {raw_path!r}")
        segments = tuple(segment for segment in raw_path.split("/") if segment)
        if not segments:
            raise SensitivePathsError(f"{where}: the path {raw_path!r} in '{key}' has no segments to match")
        paths.append(segments)
    return tuple(paths)


def scan_argv(
    argv: Sequence[str],
    command: Sequence[str],
    positionals: Sequence[str] | None,
    rules: Sequence[SensitiveRule],
) -> list[SensitiveHit]:
    """Report every hit in one invocation's own argv.

    Tokens are read one at a time and never joined, so `git config` is not `.git/config`.
    `command` and `positionals` come from the classifier. They tell an environment dump from
    an ordinary call: `env` and `printenv` leak everything when they carry no positional,
    and only a handful of commands read a bare `API_KEY` as a variable name.
    """
    hits: list[SensitiveHit] = []
    binary = os.path.basename(command[0]) if command else ""

    if binary in _ENVIRONMENT_DUMP_COMMANDS and not positionals:
        hits.append(SensitiveHit(token=argv[0] if argv else binary, rule="env-dump", source="env_dump"))

    names_variables = binary in _VARIABLE_NAME_COMMANDS
    for index, token in enumerate(argv):
        hits.extend(find_path_hits(token, "argv", rules))
        # A binary is a command name, never a variable a caller is about to print.
        if index > 0:
            secret_variable = _secret_variable_hit(token, names_variables)
            if secret_variable is not None:
                hits.append(secret_variable)

    return hits


def scan_redirects(redirects: Iterable[Redirect], rules: Sequence[SensitiveRule]) -> list[SensitiveHit]:
    """Report every hit in the redirect targets of one invocation."""
    hits: list[SensitiveHit] = []
    for redirect in redirects:
        source = _redirect_source(redirect.operator)
        if source is None:
            continue
        hits.extend(find_path_hits(redirect.target, source, rules))
    return hits


def _redirect_source(operator: str) -> str | None:
    """Return the `source` for a redirect operator, or None when its target is not a path."""
    if _WRITE_OPERATOR.fullmatch(operator):
        return "redirect_write"
    if _READ_OPERATOR.fullmatch(operator):
        return "redirect_read"
    return None


def find_path_hits(token: str, source: str, rules: Sequence[SensitiveRule]) -> list[SensitiveHit]:
    """Report every rule the token names, at most once per rule.

    The token is read three ways and a hit under any of them counts. `\\` is a separator on
    Windows and an escape on POSIX, and the two readings contradict each other: normalizing
    `\\` to `/` is what turns `.s\\sh` into the segments `.s` and `sh`, which match nothing
    while the shell still opens `.ssh`.
    """
    readings = _readings(token)
    hits: list[SensitiveHit] = []
    for rule in rules:
        if _is_excluded(rule, readings):
            continue
        hit = _first_hit(rule, readings, token, source)
        if hit is not None:
            hits.append(hit)
    return hits


def _first_hit(
    rule: SensitiveRule,
    readings: Sequence[tuple[str, list[str]]],
    token: str,
    source: str,
) -> SensitiveHit | None:
    """Match one rule against every reading, reporting the plainest reading that hits."""
    for spelling, segments in readings:
        for path in rule.paths:
            needed_glob = _locate(path, segments)
            if needed_glob is None:
                continue
            return SensitiveHit(
                token=token,
                rule=rule.name,
                source=source,
                spelling="glob" if needed_glob else spelling,
            )
    return None


def _is_excluded(rule: SensitiveRule, readings: Sequence[tuple[str, list[str]]]) -> bool:
    """Check the rule's exemptions, which never accept a glob.

    An exemption names a specific file, such as a committed `.env.example`. A glob segment
    names a set, and `fnmatch(".env.example", ".e*")` is true, so reading one backwards
    would let `cat .e*` exempt itself from the rule it just matched.
    """
    for _spelling, segments in readings:
        for path in rule.except_paths:
            if _locate(path, segments, allow_glob=False) is not None:
                return True
    return False


def _readings(token: str) -> list[tuple[str, list[str]]]:
    """Split the token into segments every way a shell might.

    Ordered by how literal the reading is, so a token that matches under more than one is
    reported under the plainest.
    """
    readings = [("literal", _split(token, "/"))]
    if "\\" in token:
        readings.append(("posix_escape", _split(_unescape(token), "/")))
        readings.append(("windows", _split(token.replace("\\", "/"), "/")))
    return readings


def _split(path: str, separator: str) -> list[str]:
    """Split a path and resolve the segments that do not name a directory of their own.

    `.` and `..` are what a path traversal is made of, and leaving them in breaks every
    multi-segment rule: `/etc/./shadow` opens `/etc/shadow` but has no two adjacent segments
    that spell it. `..` is resolved against the preceding segment, so `.aws/x/../credentials`
    reads `.aws/credentials`, while `.ssh/../x` correctly reads nothing under `.ssh`.
    """
    segments: list[str] = []
    for segment in path.split(separator):
        if not segment or segment == ".":
            continue
        if segment == ".." and segments and segments[-1] != "..":
            segments.pop()
            continue
        segments.append(segment)
    return segments


def _unescape(path: str) -> str:
    """Drop POSIX backslash escapes, so `.en\\v` reads as `.env`."""
    return re.sub(r"\\(.)", r"\1", path)


def _locate(path: Sequence[str], segments: Sequence[str], *, allow_glob: bool = True) -> bool | None:
    """Find the rule's segments inside the token's, in order and next to each other.

    Returns None when the path is absent, otherwise whether the match needed a segment of
    the token to be read as a glob.
    """
    width = len(path)
    for start in range(len(segments) - width + 1):
        needed_glob = False
        for expected, actual in zip(path, segments[start : start + width], strict=True):
            if _matches(actual, expected):
                continue
            if allow_glob and _is_glob(actual) and _matches(expected, actual):
                needed_glob = True
                continue
            break
        else:
            return needed_glob
    return None


def _matches(subject: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(subject, _bash_negations(pattern))


def _bash_negations(pattern: str) -> str:
    """Rewrite bash's `[^...]` bracket negation into the `[!...]` that fnmatch understands.

    Bash accepts both spellings. fnmatch accepts only `[!`, so `~/.[^x]sh/id_rsa` would read
    as a literal `[^x]` and match nothing while the shell opens the real key. Only a group
    that closes is rewritten: an unterminated `[` is a literal bracket to both, and a `^`
    that is not leading is an ordinary character.
    """
    if "[" not in pattern:
        return pattern
    out: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern[index] != "[":
            out.append(pattern[index])
            index += 1
            continue
        end = _bracket_end(pattern, index)
        if end is None:
            out.append(pattern[index])
            index += 1
            continue
        group = pattern[index : end + 1]
        if group.startswith("[^"):
            group = "[!" + group[2:]
        out.append(group)
        index = end + 1
    return "".join(out)


def _bracket_end(pattern: str, start: int) -> int | None:
    """Return the index of the `]` closing the group opened at `start`, or None.

    Follows fnmatch's own scanning: a `]` in the first position of a group is a literal
    member of it rather than the terminator.
    """
    index = start + 1
    if index < len(pattern) and pattern[index] in "!^":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        index += 1
    while index < len(pattern):
        if pattern[index] == "]":
            return index
        index += 1
    return None


def _is_glob(segment: str) -> bool:
    """Decide whether a token segment is specific enough to be read as a pattern."""
    if not any(character in _GLOB_METACHARACTERS for character in segment):
        return False
    literal = sum(1 for character in segment if character not in _GLOB_METACHARACTERS)
    return literal >= _MIN_GLOB_LITERAL_CHARS


def _secret_variable_hit(token: str, names_variables: bool) -> SensitiveHit | None:
    """Report a token that names an environment variable holding a secret.

    `names_variables` says whether the command reads a bare word as a variable name. When it
    does not, only the `$NAME` and `${NAME}` forms count.
    """
    name = token
    if name.startswith("${") and name.endswith("}"):
        name = name[2:-1]
    elif name.startswith("$"):
        name = name[1:]
    elif not names_variables:
        return None
    if not _ENVIRONMENT_NAME.fullmatch(name):
        return None
    if not any(_SECRET_NAME_SEGMENT.fullmatch(segment) for segment in name.split("_")):
        return None
    return SensitiveHit(token=token, rule="secret-env-var", source="argv")


def dedupe_hits(hits: Iterable[SensitiveHit]) -> list[SensitiveHit]:
    """Drop repeated hits, keeping the order in which they were found."""
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[SensitiveHit] = []
    for hit in hits:
        key = (hit.token, hit.rule, hit.source, hit.spelling)
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)
    return unique

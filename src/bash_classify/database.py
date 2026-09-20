"""Command database loading from YAML files."""

from __future__ import annotations

import os
from collections.abc import ItemsView, Iterator, KeysView, ValuesView
from pathlib import Path

import yaml

from .models import Classification, CommandDef, DelegationConfig, DelegationMode, OptionDef, Risk, SubcommandMode


def get_default_commands_dir() -> Path:
    """Return the default commands directory (bundled with the package)."""
    return Path(__file__).parent / "commands"


def get_user_commands_dir() -> Path:
    """Get the user's custom commands directory."""
    config_dir = os.environ.get("BASH_CLASSIFY_CONFIG_DIR")
    if config_dir:
        return Path(config_dir) / "commands"
    return Path.home() / ".config" / "bash-classify" / "commands"


class CommandDatabase(dict[str, CommandDef]):
    """Lazy-loading command database, read through the `Mapping` half of `dict`.

    YAML files are only parsed when a specific command is first accessed. The index of names is
    built up front, and the dict storage underneath is only the cache of what has been parsed,
    so anything that reads that storage directly sees a partial answer.

    The read surface is index-backed and safe to use: `len`, `in`, `iter`, `reversed`, `[]`,
    `get`, `keys`, `values`, `items`, `copy` and `==` against another mapping. So is the small
    mutating surface the class overrides: `[] =`, `del`, `pop`, `popitem`, `setdefault`, `clear`.

    The rest of `dict` is **not** overridden and still reads the cache: `update`, `|`, `|=`,
    `repr`, `json.dumps`, `copy.copy` (which would share `_files` by reference) and `fromkeys`.
    `popitem` also pops in index order rather than `dict`'s insertion-LIFO. Nothing in the
    package uses any of those; a caller that needs one should build a plain dict first, with
    `dict(db.items())`.
    """

    def __init__(self, builtin_dir: Path, user_dir: Path | None = None):
        super().__init__()
        # Map command name -> yaml file path, or None for a definition assigned directly.
        # This is the index every dict operation answers from; the dict storage below it is
        # only the cache of what has been parsed so far (cheap: just a filename listing).
        self._files: dict[str, Path | None] = {}

        # The bundled file a user file of the same name shadows, kept so that `extends: builtin`
        # can reach it. Indexing stays a filename listing: which of the two a name needs is
        # decided when the command is first asked for, not here.
        self._builtin_files: dict[str, Path] = {}

        # Index built-in files
        if builtin_dir.is_dir():
            for yaml_file in builtin_dir.glob("*.yaml"):
                name = _command_name_from_file(yaml_file)
                self._files[name] = yaml_file
                self._builtin_files[name] = yaml_file

        # Index user files (they replace the built-in one, or extend it -- their own choice)
        if user_dir and user_dir.is_dir():
            for yaml_file in user_dir.glob("*.yaml"):
                name = _command_name_from_file(yaml_file)
                self._files[name] = yaml_file

    def __getitem__(self, key: str) -> CommandDef:
        try:
            return super().__getitem__(key)
        except KeyError:
            pass
        path = self._files.get(key)
        if path is None:
            raise KeyError(key)
        # Lazy load and cache in the underlying dict. The bundled file is handed over only when
        # a *different* file is being loaded under this name, so nothing can extend itself.
        builtin = self._builtin_files.get(key)
        is_bundled = builtin == path
        command_def = _load_command_file(path, None if is_bundled else builtin, key, is_bundled)
        super().__setitem__(key, command_def)
        return command_def

    def __setitem__(self, key: str, value: CommandDef) -> None:
        # Register in the index too, or `__iter__` and `__len__` would not see the new command.
        self._files.setdefault(key, None)
        dict.__setitem__(self, key, value)

    def get(self, key: str, default: CommandDef | None = None) -> CommandDef | None:  # type: ignore[override]
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        return super().__contains__(key) or key in self._files

    def __iter__(self) -> Iterator[str]:
        return iter(self._files)

    def __len__(self) -> int:
        return len(self._files)

    # Everything below exists because `dict`'s own implementations read the underlying storage,
    # which holds only what has been loaded so far: `.items()` on a fresh database was empty
    # while `len()` said 160-odd, `.copy()` returned `{}`, `== {}` was True, and `pop("git")`
    # raised KeyError while `"git" in db` was True. Each now goes through `__iter__` and
    # `__getitem__`, so it sees every indexed command and loads it on demand. The views stay
    # lazy; the ones that have to produce a whole dict materialise, which is the same work a
    # real dict already did. This is the surface the class docstring lists, and no more -- the
    # C implementations of `update`, `|`, `|=` and `repr` bypass all of it.
    def keys(self) -> KeysView[str]:
        return KeysView(self)

    def values(self) -> ValuesView[CommandDef]:
        return ValuesView(self)

    def items(self) -> ItemsView[str, CommandDef]:
        return ItemsView(self)

    def __reversed__(self) -> Iterator[str]:
        return reversed(list(self._files))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CommandDatabase):
            return self._files.keys() == other._files.keys() and all(self[k] == other[k] for k in self._files)
        if isinstance(other, dict):
            return dict(self.items()) == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    __hash__ = None  # type: ignore[assignment]

    def copy(self) -> dict[str, CommandDef]:
        return dict(self.items())

    def pop(self, key: str, *default: CommandDef) -> CommandDef:
        try:
            value = self[key]
        except KeyError:
            if default:
                return default[0]
            raise
        del self[key]
        return value

    def popitem(self) -> tuple[str, CommandDef]:
        try:
            key = next(iter(self._files))
        except StopIteration:
            raise KeyError("popitem(): database is empty") from None
        return key, self.pop(key)

    def __delitem__(self, key: str) -> None:
        if key not in self._files:
            raise KeyError(key)
        del self._files[key]
        if dict.__contains__(self, key):
            dict.__delitem__(self, key)

    def clear(self) -> None:
        self._files.clear()
        dict.clear(self)

    def setdefault(self, key: str, default: CommandDef | None = None) -> CommandDef:  # type: ignore[override]
        try:
            return self[key]
        except KeyError:
            if default is None:
                raise
            self[key] = default
            return default


def _command_name_from_file(yaml_file: Path) -> str:
    """Extract command name from YAML filename.

    Handles special cases: true.yaml, false.yaml, yes.yaml where
    the stem would be parsed as boolean by YAML but the filename is fine.
    """
    return yaml_file.stem


_EXTENDS_BUILTIN = "builtin"
"""The only accepted value of the top-level `extends` key."""

# A `delegates_to` block is one setting, not a namespace: `mode` decides which of its other
# fields mean anything, so half of a user's block merged into half of the bundled one would
# not be a configuration anyone wrote. Every other mapping -- `subcommands`, `options`,
# `global_options`, and a single subcommand's or option's own fields -- is a namespace of
# independent entries and merges key by key.
_OPAQUE_MERGE_KEYS = frozenset({"delegates_to"})

# The two maps whose entries the bundled files may reach under a second spelling. A user key
# that a bundled entry claims as an alias cannot merge into it, so it is rejected rather than
# silently shadowing it -- see `_reject_option_alias_shadowing`.
_OPTION_MAP_KEYS = frozenset({"options", "global_options"})


def _read_command_document(yaml_file: Path) -> dict:
    """Read one YAML command file and check its outermost shape."""
    with open(yaml_file) as f:
        data = yaml.safe_load(f)

    if data is None:
        raise ValueError("Empty YAML file")

    if not isinstance(data, dict):
        raise ValueError(f"Expected a YAML mapping, got {type(data).__name__}")

    return data


def _take_extends(data: dict, command_name: str) -> str | None:
    """Pop and validate the top-level `extends` key, returning None when there is none."""
    if "extends" not in data:
        return None

    value = data.pop("extends")
    if value != _EXTENDS_BUILTIN:
        raise ValueError(f"command '{command_name}': 'extends' must be '{_EXTENDS_BUILTIN}', got {value!r}")
    if "alias_of" in data:
        raise ValueError(
            f"command '{command_name}': 'extends' and 'alias_of' are mutually exclusive; "
            f"an alias file points at another command instead of defining one"
        )
    return str(value)


def _blank_valued_keys(data: dict, prefix: str = "") -> list[str]:
    """Return the dotted path of every key in `data` written with no value, at any depth."""
    blank: list[str] = []
    for key, value in data.items():
        path = f"{prefix}{_yaml_str(key)}"
        if value is None:
            blank.append(path)
        elif isinstance(value, dict):
            blank.extend(_blank_valued_keys(value, f"{path}."))
    return blank


def _reject_blank_values(data: dict, command_name: str) -> None:
    """Fail on a key an extending file wrote with no value.

    YAML reads `classification:` with nothing after it as the value `None`, and every parser
    below reads `None` as "not set, use the default". In a file that stands alone that is
    harmless -- the default is what a missing key would have given anyway. In a file that
    extends a bundled one it is not: the `None` overwrites the bundled value, and the default
    it falls back to is always the weaker answer. `classification:` on a user `git.yaml`
    turned `git <anything unrecognised>` from DANGEROUS into READONLY, and a bare `push:`
    under `subcommands:` did the same to `git push`.

    So a blank key is a load error here, in the same spirit as an unrecognised one: half a
    line typed, or a value commented out while its author thinks, must not read as consent.
    An entry the author means to leave at its defaults is written `{}`, which merges as the
    no-op it looks like.
    """
    blank = _blank_valued_keys(data)
    if not blank:
        return
    raise ValueError(
        f"command '{command_name}': extending the bundled definition, so every key must carry a value, "
        f"but {', '.join(repr(path) for path in blank)} "
        f"{'is' if len(blank) == 1 else 'are'} null -- which is also what a key written with nothing "
        f"after it means. A null does not leave the bundled value alone: it replaces it with the "
        f"default, which is the weaker answer. Write the value, delete the line, or -- for a "
        f"subcommand or option entry meant to keep its bundled settings -- write '{{}}'"
    )


def _reject_option_alias_shadowing(base: dict, overlay: dict, command_name: str, where: str) -> None:
    """Fail on a user option written under a name a bundled entry claims as its alias.

    Aliases are expanded after the merge, in file order, so an entry the user adds under an
    alias spelling does not change the bundled option -- it is a separate definition built
    from defaults, and whichever of the two the expansion writes last wins. `kubectl.yaml`
    spells `-n` only as an alias of `--namespace`, so a user entry for `-n` stopped it
    consuming its value and `kubectl -n prod delete pod x` fell from DANGEROUS to
    EXTERNAL_EFFECTS. Whether a given option merged or shadowed depended on whether the
    bundled file happened to also list the alias as a key of its own, which is no rule at all.
    """
    claimed: dict[str, str] = {}
    for name, props in base.items():
        if not isinstance(props, dict):
            continue
        # A user entry for this option may itself rewrite the alias list, and a list replaces
        # rather than merges. So an author releasing `-n` from `--namespace` and keying `-n`
        # on its own in the same file is asking for exactly what the merge would produce, and
        # is not shadowing anything -- the claim has to be read after their rewrite, not before.
        overlay_props = overlay.get(name)
        if isinstance(overlay_props, dict) and "aliases" in overlay_props:
            aliases = overlay_props["aliases"]
        else:
            aliases = props.get("aliases")
        for alias in aliases or []:
            alias = _yaml_str(alias)
            if alias != _yaml_str(name):
                claimed[alias] = _yaml_str(name)

    for name in overlay:
        primary = claimed.get(_yaml_str(name))
        if primary is not None:
            raise ValueError(
                f"command '{command_name}': '{where}' declares '{name}', which the bundled file spells "
                f"as an alias of '{primary}'. An entry under an alias shadows the bundled option instead "
                f"of changing it; write it under '{primary}' instead"
            )


def _read_base_document(builtin_file: Path | None, command_name: str, index_name: str, is_bundled: bool) -> dict:
    """Read the bundled document an `extends: builtin` file builds on."""
    if builtin_file is None and is_bundled:
        raise ValueError(
            f"command '{command_name}': 'extends: {_EXTENDS_BUILTIN}' is only for a user database file, "
            f"and this file is itself the bundled definition of '{index_name}'"
        )
    if builtin_file is None:
        raise ValueError(
            f"command '{command_name}': 'extends: {_EXTENDS_BUILTIN}' has nothing to extend, "
            f"because the bundled database has no '{index_name}.yaml'"
        )

    try:
        base = _read_command_document(builtin_file)
    except Exception as e:
        raise ValueError(f"cannot read the bundled definition at {builtin_file}: {e}") from e

    if "extends" in base:
        raise ValueError(f"the bundled definition at {builtin_file} declares 'extends' itself")

    return base


def _merge_command_data(base: dict, overlay: dict, command_name: str, path: str = "") -> dict:
    """Merge a user document over the bundled document it extends.

    Mappings merge key by key at every depth; a scalar, a list or a `delegates_to` block in
    the overlay replaces its counterpart outright. So a user file adds to what the bundled
    file knows and overrides only the fields it names: declaring `push: {risk: LOW}` keeps
    `push`'s bundled classification and its `--force` override, rather than deleting them.

    The merge never drops a subcommand or an option, which is the guarantee worth having.
    It is not a blanket "cannot remove": a list is replaced, so `aliases: []` does drop the
    bundled aliases, and that is the one deliberate way to take something away. The
    accidental ways are closed elsewhere -- `_reject_blank_values` before this runs, because
    YAML's `None` for a key with no value is a value like any other here and would delete,
    and `_parse_delegation_config` for an empty `delegates_to` block.
    """
    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if key in _OPAQUE_MERGE_KEYS or not isinstance(existing, dict) or not isinstance(value, dict):
            merged[key] = value
            continue
        if key in _OPTION_MAP_KEYS:
            _reject_option_alias_shadowing(existing, value, command_name, f"{path}{_yaml_str(key)}")
        merged[key] = _merge_command_data(existing, value, command_name, f"{path}{_yaml_str(key)}.")
    return merged


def _load_command_file(
    yaml_file: Path,
    builtin_file: Path | None = None,
    index_name: str | None = None,
    is_bundled: bool = False,
) -> CommandDef:
    """Parse a single YAML command file into a CommandDef.

    `builtin_file` is the bundled file of the same name that `yaml_file` shadows, if there is
    one. It is read only when `yaml_file` asks for it with `extends: builtin`, so the common
    case still parses exactly one file. `index_name` is the name the database filed this file
    under -- its filename stem, which is what the bundled lookup is keyed on, and not
    necessarily the `command:` inside it. `is_bundled` says `yaml_file` is itself the bundled
    definition, so there is nothing above it to extend.
    """
    try:
        data = _read_command_document(yaml_file)

        if "command" not in data:
            raise ValueError("missing required field 'command'")
        command_name = _yaml_str(data["command"])

        if _take_extends(data, command_name) is not None:
            # Validate the user's own document first, so a key that is both misspelled and
            # blank is reported as the misspelling it is. Reading it twice is cheap, and the
            # merged document would otherwise answer "give it a value" for a key that has no
            # value to give.
            _parse_command_def(dict(data), command_name)
            _reject_blank_values(data, command_name)
            base = _read_base_document(builtin_file, command_name, index_name or yaml_file.stem, is_bundled)
            data = _merge_command_data(base, data, command_name)

        return _parse_command_def(data, command_name)
    except Exception as e:
        raise ValueError(f"Error loading {yaml_file}: {e}") from e


def load_database(commands_dir: Path | None = None) -> CommandDatabase:
    """Load command database with lazy per-command loading.

    Args:
        commands_dir: Explicit commands directory. When provided,
                      user overrides are NOT loaded.

    Returns:
        A CommandDatabase mapping command names to their CommandDef definitions.
    """
    builtin_dir = commands_dir or get_default_commands_dir()
    user_dir = None
    if commands_dir is None:
        candidate = get_user_commands_dir()
        if candidate.is_dir():
            user_dir = candidate
    return CommandDatabase(builtin_dir, user_dir)


def _load_commands_from_dir(commands_dir: Path) -> dict[str, CommandDef]:
    """Load all command definitions from YAML files in the given directory.

    This eagerly loads all commands at once. Useful for schema validation
    and tests that need to iterate all commands.

    Args:
        commands_dir: Path to directory containing YAML command definitions.

    Returns:
        A dict mapping command names to their CommandDef definitions.
    """
    database: dict[str, CommandDef] = {}

    for yaml_file in sorted(commands_dir.glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)

            if data is None:
                continue

            if not isinstance(data, dict):
                raise ValueError(f"Expected a YAML mapping, got {type(data).__name__}")

            command_name = _yaml_str(data["command"])  # YAML parses true/false as booleans
            command_def = _parse_command_def(data, command_name)
            database[command_name] = command_def
        except Exception as e:
            raise ValueError(f"Error loading {yaml_file}: {e}") from e

    return database


def _yaml_str(value: object) -> str:
    """Convert a YAML value to string, handling booleans correctly.

    YAML parses bare `true`/`false` as Python booleans, but we need them as
    lowercase strings (e.g. for the `true` and `false` commands).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


_ALIAS_FORBIDDEN_KEYS = frozenset(
    {
        "classification",
        "risk",
        "subcommands",
        "options",
        "global_options",
        "subcommand_mode",
        "delegates_to",
        "strict",
    }
)

# The keys each kind of object accepts. These mirror the `additionalProperties: false` objects
# in schemas/command.schema.json, and exist because only the bundled files are schema-validated
# in CI: a user database is read by this loader alone. An unrecognised key there used to be
# ignored, so `clasification: READONLY` silently left the command at its default rather than
# saying anything, and the misspelling of a key that *lowers* a classification is exactly the
# direction that must not fail quietly.
_COMMAND_KEYS = frozenset(
    {
        "command",
        "description",
        "alias_of",
        "classification",
        "risk",
        "strict",
        "global_options",
        "options",
        "subcommands",
        "subcommand_mode",
        "delegates_to",
    }
)

_SUBCOMMAND_KEYS = frozenset(
    {
        "aliases",
        "classification",
        "risk",
        "strict",
        "options",
        "subcommands",
        "subcommand_mode",
        "delegates_to",
    }
)

_OPTION_KEYS = frozenset(
    {
        "takes_value",
        "aliases",
        "overrides",
        "risk",
        "captures_directory",
        "names_output_path",
        "before_subcommand_only",
        "delegates_to",
    }
)

_DELEGATION_KEYS = frozenset(
    {
        "mode",
        "separator",
        "terminator",
        "flag",
        "strip_assignments",
        "skip_leading_positionals",
        "min_classification",
    }
)


def _reject_unknown_keys(data: object, known: frozenset[str], subject: str) -> None:
    """Fail on any key `known` does not list, naming both the typo and the accepted keys."""
    if not isinstance(data, dict):
        raise ValueError(f"{subject}: expected a mapping, got {type(data).__name__}")
    unknown = sorted(str(key) for key in data.keys() - known)
    if unknown:
        raise ValueError(f"{subject}: unknown field(s) {', '.join(unknown)}; accepted: {', '.join(sorted(known))}")


def _parse_command_def(data: dict, command_name: str, is_subcommand: bool = False) -> CommandDef:
    """Parse a raw YAML dict into a CommandDef structure.

    `is_subcommand` distinguishes an entry under a `subcommands` map from the top level of
    a command file. Only the former may carry `aliases`; a command file names itself by its
    filename, so a second name for it is a separate `alias_of` file.
    """
    if "aliases" in data and not is_subcommand:
        raise ValueError(
            f"command '{command_name}': 'aliases' is only valid on subcommands; "
            f"use an alias_of file for a command-level alias"
        )

    if is_subcommand:
        _reject_unknown_keys(data, _SUBCOMMAND_KEYS, f"subcommand '{command_name}'")
    else:
        _reject_unknown_keys(data, _COMMAND_KEYS, f"command '{command_name}'")

    alias_of = data.get("alias_of")
    if alias_of is not None:
        conflicting = sorted(_ALIAS_FORBIDDEN_KEYS & data.keys())
        if conflicting:
            raise ValueError(
                f"alias file for '{command_name}' has alias_of='{alias_of}' "
                f"combined with forbidden field(s): {', '.join(conflicting)}"
            )
        return CommandDef(command=command_name, alias_of=str(alias_of))

    classification = _parse_classification(data.get("classification"))
    risk = _parse_risk(data.get("risk"))

    global_options = _parse_options(data.get("global_options", {}), "global_options")
    options = _parse_options(data.get("options", {}))
    subcommands = _parse_subcommands(data.get("subcommands", {}))
    delegates_to = _parse_delegation_config(data.get("delegates_to"))
    strict = data.get("strict", True)
    subcommand_mode = _parse_subcommand_mode(data.get("subcommand_mode"))

    return CommandDef(
        command=command_name,
        aliases=_parse_aliases(data.get("aliases"), command_name),
        classification=classification,
        risk=risk,
        global_options=global_options,
        subcommands=subcommands,
        options=options,
        strict=strict,
        subcommand_mode=subcommand_mode,
        delegates_to=delegates_to,
    )


def _parse_classification(value: str | None) -> Classification | None:
    """Parse a classification string into a Classification enum."""
    if value is None:
        return None
    return Classification(value)


def _parse_risk(value: str | None) -> Risk | None:
    """Parse a risk string into a Risk enum."""
    if value is None:
        return None
    return Risk(value)


def _parse_subcommand_mode(value: str | None) -> SubcommandMode:
    """Parse a subcommand_mode string into a SubcommandMode enum."""
    if value is None:
        return SubcommandMode.HIERARCHICAL
    return SubcommandMode(value)


def _parse_options(raw: dict | None, field: str = "options") -> dict[str, OptionDef]:
    """Parse an options map, expanding aliases so each alias maps to the same OptionDef."""
    if not raw:
        return {}

    if not isinstance(raw, dict):
        raise ValueError(f"'{field}' must be a mapping of option name to definition, got {type(raw).__name__}")

    options: dict[str, OptionDef] = {}

    for name, props in raw.items():
        if props is None:
            props = {}

        _reject_unknown_keys(props, _OPTION_KEYS, f"option '{name}'")

        option_def = OptionDef(
            takes_value=props.get("takes_value", False),
            aliases=props.get("aliases", []),
            overrides=_parse_classification(props.get("overrides")),
            risk=_parse_risk(props.get("risk")),
            captures_directory=props.get("captures_directory", False),
            names_output_path=props.get("names_output_path", False),
            before_subcommand_only=props.get("before_subcommand_only", False),
            delegates_to=_parse_delegation_config(props.get("delegates_to")),
        )

        # Store under the primary name
        options[name] = option_def

        # Expand aliases so lookup works by any name
        for alias in option_def.aliases:
            options[alias] = option_def

    return options


def _parse_aliases(raw: object, command_name: str) -> list[str]:
    """Parse the `aliases` list of a subcommand definition."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"subcommand '{command_name}': 'aliases' must be a list of strings")
    return [_yaml_str(alias) for alias in raw]


def _parse_subcommands(raw: dict | None) -> dict[str, CommandDef]:
    """Parse a subcommands map recursively.

    Each alias is registered in the same map as the definition it belongs to, pointing at
    that very object, so `_match_subcommand` finds it by the typed word and still reports
    the canonical name. An alias that would shadow a real sibling subcommand, or that two
    siblings claim, is rejected here rather than silently resolving to one of them.
    """
    if not raw:
        return {}

    if not isinstance(raw, dict):
        raise ValueError(f"'subcommands' must be a mapping of subcommand name to definition, got {type(raw).__name__}")

    subcommands: dict[str, CommandDef] = {}

    for name, props in raw.items():
        if props is None:
            props = {}
        canonical = _yaml_str(name)
        subcommands[canonical] = _parse_command_def(props, canonical, is_subcommand=True)

    aliased_by: dict[str, str] = {}
    for canonical, definition in list(subcommands.items()):
        for alias in definition.aliases:
            if alias in subcommands:
                raise ValueError(
                    f"subcommand '{canonical}' declares alias '{alias}', "
                    f"which is already a subcommand of the same parent"
                )
            if alias in aliased_by:
                raise ValueError(
                    f"subcommand '{canonical}' declares alias '{alias}', "
                    f"which is already an alias of subcommand '{aliased_by[alias]}'"
                )
            aliased_by[alias] = canonical

    for alias, canonical in aliased_by.items():
        subcommands[alias] = subcommands[canonical]

    return subcommands


def _parse_delegation_config(raw: dict | None) -> DelegationConfig | None:
    """Parse a delegates_to configuration.

    An absent key is the only way to say "this command does not delegate". A key that is
    present but carries nothing to act on -- `{}`, or an empty list -- used to return `None`
    just the same, which reads as that same statement without anyone having made it. It is
    the costly direction: dropping `xargs`'s delegation makes `xargs rm -rf` READONLY instead
    of DANGEROUS. The schema has always required `mode` here; this is the loader agreeing.
    """
    if raw is None:
        return None

    _reject_unknown_keys(raw, _DELEGATION_KEYS, "delegates_to")

    if "mode" not in raw:
        raise ValueError(
            "delegates_to: missing required field 'mode'; omit the key entirely for a command that "
            "does not delegate, because an empty block reads as one that does not either"
        )

    mode = DelegationMode(raw["mode"])
    min_class = _parse_classification(raw.get("min_classification"))

    return DelegationConfig(
        mode=mode,
        separator=raw.get("separator"),
        terminator=raw.get("terminator"),
        flag=raw.get("flag"),
        strip_assignments=raw.get("strip_assignments", False),
        skip_leading_positionals=raw.get("skip_leading_positionals", 0),
        min_classification=min_class,
    )

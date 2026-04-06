"""Command database loading from YAML files."""

from __future__ import annotations

import os
from collections.abc import Iterator
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
    """Lazy-loading command database that behaves as a dict.

    YAML files are only parsed when a specific command is first accessed.
    From the outside, this is indistinguishable from a regular dict.
    """

    def __init__(self, builtin_dir: Path, user_dir: Path | None = None):
        super().__init__()
        # Map command name -> yaml file path (cheap: just filename listing)
        self._files: dict[str, Path] = {}

        # Index built-in files
        if builtin_dir.is_dir():
            for yaml_file in builtin_dir.glob("*.yaml"):
                name = _command_name_from_file(yaml_file)
                self._files[name] = yaml_file

        # Index user files (override built-in)
        if user_dir and user_dir.is_dir():
            for yaml_file in user_dir.glob("*.yaml"):
                name = _command_name_from_file(yaml_file)
                self._files[name] = yaml_file  # user overrides built-in

    def __getitem__(self, key: str) -> CommandDef:
        try:
            return super().__getitem__(key)
        except KeyError:
            pass
        if key not in self._files:
            raise KeyError(key)
        # Lazy load and cache in the underlying dict
        command_def = _load_command_file(self._files[key])
        super().__setitem__(key, command_def)
        return command_def

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


def _command_name_from_file(yaml_file: Path) -> str:
    """Extract command name from YAML filename.

    Handles special cases: true.yaml, false.yaml, yes.yaml where
    the stem would be parsed as boolean by YAML but the filename is fine.
    """
    return yaml_file.stem


def _load_command_file(yaml_file: Path) -> CommandDef:
    """Parse a single YAML command file into a CommandDef."""
    try:
        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        if data is None:
            raise ValueError("Empty YAML file")

        if not isinstance(data, dict):
            raise ValueError(f"Expected a YAML mapping, got {type(data).__name__}")

        command_name = _yaml_str(data["command"])
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


def _parse_command_def(data: dict, command_name: str) -> CommandDef:
    """Parse a raw YAML dict into a CommandDef structure."""
    classification = _parse_classification(data.get("classification"))
    risk = _parse_risk(data.get("risk"))

    global_options = _parse_options(data.get("global_options", {}))
    options = _parse_options(data.get("options", {}))
    subcommands = _parse_subcommands(data.get("subcommands", {}))
    delegates_to = _parse_delegation_config(data.get("delegates_to"))
    strict = data.get("strict", True)
    subcommand_mode = _parse_subcommand_mode(data.get("subcommand_mode"))

    return CommandDef(
        command=command_name,
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


def _parse_options(raw: dict | None) -> dict[str, OptionDef]:
    """Parse an options map, expanding aliases so each alias maps to the same OptionDef."""
    if not raw:
        return {}

    options: dict[str, OptionDef] = {}

    for name, props in raw.items():
        if props is None:
            props = {}

        option_def = OptionDef(
            takes_value=props.get("takes_value", False),
            aliases=props.get("aliases", []),
            overrides=_parse_classification(props.get("overrides")),
            risk=_parse_risk(props.get("risk")),
            captures_directory=props.get("captures_directory", False),
            delegates_to=_parse_delegation_config(props.get("delegates_to")),
        )

        # Store under the primary name
        options[name] = option_def

        # Expand aliases so lookup works by any name
        for alias in option_def.aliases:
            options[alias] = option_def

    return options


def _parse_subcommands(raw: dict | None) -> dict[str, CommandDef]:
    """Parse a subcommands map recursively."""
    if not raw:
        return {}

    subcommands: dict[str, CommandDef] = {}

    for name, props in raw.items():
        if props is None:
            props = {}
        subcommands[name] = _parse_command_def(props, name)

    return subcommands


def _parse_delegation_config(raw: dict | None) -> DelegationConfig | None:
    """Parse a delegates_to configuration."""
    if not raw:
        return None

    mode = DelegationMode(raw["mode"])
    min_class = _parse_classification(raw.get("min_classification"))

    return DelegationConfig(
        mode=mode,
        separator=raw.get("separator"),
        terminator=raw.get("terminator"),
        flag=raw.get("flag"),
        strip_assignments=raw.get("strip_assignments", False),
        min_classification=min_class,
    )

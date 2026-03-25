"""Command database loading from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import Classification, CommandDef, DelegationConfig, DelegationMode, OptionDef


def get_default_commands_dir() -> Path:
    """Return the default commands directory (bundled with the package)."""
    return Path(__file__).parent / "commands"


def load_database(commands_dir: Path | None = None) -> dict[str, CommandDef]:
    """Load all command definitions from YAML files in the given directory.

    Args:
        commands_dir: Path to directory containing YAML command definitions.
                      Defaults to get_default_commands_dir().

    Returns:
        A dict mapping command names to their CommandDef definitions.
    """
    if commands_dir is None:
        commands_dir = get_default_commands_dir()

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

    global_options = _parse_options(data.get("global_options", {}))
    options = _parse_options(data.get("options", {}))
    subcommands = _parse_subcommands(data.get("subcommands", {}))
    delegates_to = _parse_delegation_config(data.get("delegates_to"))
    strict = data.get("strict", True)

    return CommandDef(
        command=command_name,
        classification=classification,
        global_options=global_options,
        subcommands=subcommands,
        options=options,
        strict=strict,
        delegates_to=delegates_to,
    )


def _parse_classification(value: str | None) -> Classification | None:
    """Parse a classification string into a Classification enum."""
    if value is None:
        return None
    return Classification(value)


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

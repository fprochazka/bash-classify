"""Validate all YAML command files against the JSON Schema."""

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "command.schema.json"
COMMANDS_DIR = Path(__file__).parent.parent / "src" / "bash_classify" / "commands"
MATCH_RULES_SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "match-rules.schema.json"
MATCH_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "match"


@pytest.fixture(scope="session")
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def match_rules_schema():
    with open(MATCH_RULES_SCHEMA_PATH) as f:
        return json.load(f)


def yaml_files():
    return sorted(COMMANDS_DIR.glob("*.yaml"))


def match_rules_files():
    return sorted(MATCH_FIXTURES_DIR.glob("*/rules.yaml"))


@pytest.mark.parametrize("yaml_file", yaml_files(), ids=lambda p: p.stem)
def test_yaml_validates_against_schema(yaml_file, schema):
    with open(yaml_file) as f:
        data = yaml.safe_load(f)
    jsonschema.validate(instance=data, schema=schema)


@pytest.mark.parametrize("rules_file", match_rules_files(), ids=lambda p: p.parent.name)
def test_match_rules_validate_against_schema(rules_file, match_rules_schema):
    with open(rules_file) as f:
        data = yaml.safe_load(f)
    jsonschema.validate(instance=data, schema=match_rules_schema)

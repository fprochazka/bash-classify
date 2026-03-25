# bash-classify

Classify bash commands by their side-effect risk level.

## What it does

bash-classify parses bash expressions using tree-sitter, classifies each command against a database of 120+ known commands, and outputs a structured JSON verdict. Commands are classified into four levels: `READONLY`, `WRITE`, `DANGEROUS`, and `UNKNOWN`.

Designed primarily as a [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook to automatically allow safe, read-only commands while flagging risky ones for human review.

## Installation

```bash
uv tool install bash-classify
# or
pip install bash-classify
```

## Quick start

```bash
$ echo 'kubectl get pods -n production' | bash-classify | jq '.classification'
"READONLY"

$ echo 'git push --force origin main' | bash-classify | jq '.classification'
"DANGEROUS"

$ echo 'cp file.txt /etc/config' | bash-classify | jq '.classification'
"DANGEROUS"

$ echo 'find . -name "*.pyc" -delete' | bash-classify | jq '.classification'
"DANGEROUS"
```

## Claude Code plugin

The repo includes a Claude Code plugin that auto-allows readonly bash commands via a `PreToolUse` hook. Install it as a marketplace:

```bash
# First, install the bash-classify CLI
uv tool install bash-classify

# Then install the plugin marketplace
claude plugin add /path/to/bash-classify
```

Or from GitHub directly:

```bash
claude plugin add https://github.com/fprochazka/bash-classify
```

Once installed, any Bash tool call classified as `READONLY` is auto-approved — no permission prompt. Everything else (WRITE, DANGEROUS, UNKNOWN) still requires confirmation.

## Command database

The classification database includes 120+ command definitions covering common Unix utilities, package managers, container tools, cloud CLIs, and more.

- See [docs/classification-guidance.md](docs/classification-guidance.md) for how to add new commands
- YAML definitions are validated against a JSON Schema for IDE autocomplete and CI checks

## Classification levels

| Level | Description | Examples |
|---|---|---|
| `READONLY` | No side effects, safe to auto-approve | `ls`, `cat`, `grep`, `kubectl get` |
| `WRITE` | Modifies local files or state | `mkdir`, `cp`, `git commit` |
| `DANGEROUS` | Destructive, system-wide, or irreversible | `rm -rf`, `git push --force`, `chmod` |
| `UNKNOWN` | Command not in database | Any unrecognized command |

## How it works

- **Tree-sitter parsing** -- bash expressions are parsed into an AST for accurate command extraction, handling pipes, subshells, and command substitution
- **YAML command database** -- each command has classification rules with subcommand and option matching
- **Subcommand matching** -- `kubectl get` and `kubectl delete` can have different classifications
- **Delegation for wrappers** -- commands like `xargs`, `sudo`, and `env` delegate classification to the inner command

## Python API

```python
from bash_classify import classify_expression

result = classify_expression("kubectl get pods")
print(result.classification)  # Classification.READONLY
```

See [SPEC.md](SPEC.md) for the full specification.

## Development

```bash
git clone https://github.com/fprochazka/bash-classify.git
cd bash-classify
uv sync --dev
```

Run tests and linting before committing:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
```

To add or modify command definitions, see [docs/classification-guidance.md](docs/classification-guidance.md). All YAML files in `src/bash_classify/commands/` are validated against a [JSON Schema](schemas/command.schema.json) — your IDE will provide autocomplete if it supports the `# $schema:` comment.

## Releasing

Version is derived automatically from git tags via `hatch-vcs` — no manual version bumping needed.

```bash
git tag v<version>
git push origin v<version>
```

The `publish.yml` GitHub Action builds and publishes to PyPI automatically via trusted publishing.

## License

[MIT](LICENSE)

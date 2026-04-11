# bash-classify

Classify bash commands by their side-effect risk level.

## What it does

bash-classify parses bash expressions using tree-sitter, classifies each command against a database of 150+ known commands, and outputs a structured JSON verdict. Commands are classified along two axes: **classification** (`READONLY`, `LOCAL_EFFECTS`, `EXTERNAL_EFFECTS`, `DANGEROUS`, `UNKNOWN`) describing what kind of effects a command has, and **risk** (`LOW`, `MEDIUM`, `HIGH`) describing how worried you should be.

Designed primarily as a [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook to automatically allow low-risk commands while flagging risky ones for human review.

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

The repo includes a Claude Code plugin that auto-allows low-risk bash commands via a `PreToolUse` hook.

```bash
# Install the bash-classify CLI
uv tool install bash-classify

# Add the marketplace and install the plugin
claude plugin marketplace add fprochazka/bash-classify
claude plugin install bash-classify-hook@fprochazka-bash-classify
```

To upgrade after a new release:

```bash
uv tool install --force bash-classify
claude plugin marketplace update fprochazka-bash-classify
claude plugin update bash-classify-hook@fprochazka-bash-classify
```

Once installed, any Bash tool call with `risk: LOW` is auto-approved — no permission prompt. This includes all `READONLY` commands plus safe routine operations like `git add`, `git commit`, `mkdir`, package installs, code formatters, and more. Commands with `MEDIUM` or `HIGH` risk still require confirmation.

## Command database

The classification database includes 150+ command definitions covering common Unix utilities, package managers, container tools, cloud CLIs, and more.

- See [docs/classification-guidance.md](docs/classification-guidance.md) for how to add new commands
- YAML definitions are validated against a JSON Schema for IDE autocomplete and CI checks

## Classification levels

| Level | Description | Examples |
|---|---|---|
| `READONLY` | No side effects | `ls`, `cat`, `grep`, `kubectl get` |
| `LOCAL_EFFECTS` | Modifies local files or state only | `git add`, `git commit`, `cp`, `mkdir`, `pytest` |
| `EXTERNAL_EFFECTS` | Interacts with external systems | `git push`, `kubectl apply`, `curl -d` |
| `DANGEROUS` | Destructive, system-wide, or irreversible | `rm -rf`, `git push --force`, `chmod` |
| `UNKNOWN` | Command not in database | Any unrecognized command |

## Risk levels

Each command also gets a **risk** rating, orthogonal to classification:

| Risk | Description | Examples |
|---|---|---|
| `LOW` | Safe, routine operation — auto-approved | `ls`, `git add`, `git commit`, `mkdir`, `ruff format` |
| `MEDIUM` | Normal caution warranted | `git push`, `cp`, `npm run`, `git rebase` |
| `HIGH` | Dangerous or unknown — always requires confirmation | `rm -rf`, `git push --force`, unknown commands |

Risk defaults are derived from classification (`READONLY`→LOW, `LOCAL_EFFECTS`→MEDIUM, `EXTERNAL_EFFECTS`→MEDIUM, `DANGEROUS`/`UNKNOWN`→HIGH) but can be overridden per command, subcommand, or option in the YAML database.

## How it works

- **Tree-sitter parsing** -- bash expressions are parsed into an AST for accurate command extraction, handling pipes, subshells, and command substitution
- **YAML command database** -- each command has classification rules with subcommand and option matching
- **Subcommand matching** -- `kubectl get` and `kubectl delete` can have different classifications
- **Multi-goal build tools** -- `subcommand_mode: match_all` handles commands like `mvn clean install` and `gradle clean build test` where multiple goals can be combined in any order
- **Delegation for wrappers** -- commands like `xargs`, `sudo`, and `env` delegate classification to the inner command
- **File path detection** -- redirect operators (`>`, `>>`, `<`) are parsed into `write_paths`/`read_paths` in the output; writes to `/tmp` and `/var/tmp` stay at LOW risk

## Python API

```python
from bash_classify import classify_expression

result = classify_expression("kubectl get pods")
print(result.classification)  # Classification.READONLY
print(result.risk)            # Risk.LOW
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

Before tagging, bump the version in both plugin manifest files:

- `coding-agent-plugins/claude-code/.claude-plugin/plugin.json`
- `.claude-plugin/marketplace.json`

Wait for CI to pass on master, then tag, push, and create a GitHub release:

```bash
# Review changes since last release
git log $(git describe --tags --abbrev=0)..HEAD --oneline

git tag v<version>
git push origin v<version>
gh release create v<version> --title "v<version>" --notes "..."
```

The `publish.yml` GitHub Action builds and publishes to PyPI automatically via trusted publishing.

## License

[MIT](LICENSE)

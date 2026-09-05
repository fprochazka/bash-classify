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

## Matching command shapes

Classification answers "how risky is this?". A deny hook usually has a narrower question:
"does this expression run command shape X?" `bash-classify match` answers that one. It
parses the expression, walks every invocation at every depth, and reports which of the
shapes in a rules file were actually invoked — so a heredoc body, an `echo` string, a
`#` comment or a `grep` pattern that merely *names* the command does not count.

```yaml
# blocked-commands.yaml
rules:
  - name: mr-discussions-api
    command: [glab, api]
    any_arg_matches: 'merge_requests/[^/?]+/(discussions|notes)(/|\?|$)'

  - name: mr-view-comments
    command: [glab, mr, view]
    any_option: [--comments, -c]

  - name: mr-note
    command: [glab, mr, note]
    except: [[glab, mr, note, list]]
```

```bash
$ echo 'sudo glab mr note 42 -m hi' | bash-classify match --rules blocked-commands.yaml
{
  "matches": [
    {
      "rule": "mr-note",
      "command": ["glab", "mr", "note"],
      "argv": ["glab", "mr", "note", "42", "-m", "hi"],
      "via": ["sudo"]
    }
  ],
  "parse_warnings": []
}
```

Within one rule every condition given must hold; rules are independent of each other, and
one invocation can match several. `command` is a prefix match against the *resolved*
command path, so `/usr/bin/glab --repo x mr note` still resolves to `glab mr note`.
`any_option` looks at the options actually present, with values stripped and declared
clusters expanded (`-wc` carries `-c`). `any_arg_matches` is a Python `re.search` over
every argument token — a pattern written for `grep -E` needs `\S` rather than
`[^[:space:]]`. `via` lists the enclosing wrappers, outermost first.

**Two things a caller has to check.** First, `parse_warnings` is always present: when it
is non-empty the expression could not be fully parsed, so an empty `matches` proves nothing
and the caller should fall back to whatever it did before. Second, check that the output
actually has a `matches` key. A `bash-classify` older than this mode does not reject the
unknown `match` argument — it ignores it, classifies stdin and exits 0, so the caller gets
a normal classification JSON with no `matches` key. Treat a non-zero exit, unparseable
output, or output without a `matches` key as "cannot answer" and fall back; never read a
missing `matches` as "nothing matched".

Exit codes are `0` whether or not anything matched, `1` for empty input or no input within
5 seconds, and `2` for bad arguments, an unreadable or invalid rules file, or an internal
error.

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

bash-classify loads command definitions from two locations:

- **Built-in database** — 150+ command definitions bundled with the package, covering common Unix utilities, package managers, container tools, cloud CLIs, and more. Lives in `src/bash_classify/commands/*.yaml`.
- **User database** — your own command definitions at `~/.config/bash-classify/commands/*.yaml` (override the location with the `BASH_CLASSIFY_CONFIG_DIR` env var, which resolves to `$BASH_CLASSIFY_CONFIG_DIR/commands/`). User files with the same name as a built-in override it completely, so you can customize classifications for internal tools, company-specific wrappers, or personal CLIs without forking the repo.

Both directories use the same YAML format. See [docs/classification-guidance.md](docs/classification-guidance.md) for how to add new commands. YAML definitions are validated against a [JSON Schema](schemas/command.schema.json) for IDE autocomplete and CI checks.

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
- **Subcommand aliases** -- a subcommand can declare other names for itself, so `glab pipeline view` resolves to `glab ci view` and any rule written for the canonical name catches the aliased spelling
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

Each command result carries the options it actually uses and the positionals left after parsing. Option values
are stripped, so `--key=value` shows up as `--key` and `-fvalue` as `-f`:

```python
command = classify_expression("git commit --amend -m 'wip'").commands[0]
print(command.command)      # ['git', 'commit']
print(command.options)      # ['--amend', '-m']
print(command.positionals)  # []
```

`iter_invocations` walks every invocation in an expression depth-first — top-level commands and, recursively,
the inner commands that wrappers such as `sudo`, `timeout` or `bash -c` delegate to. It yields each invocation
with its `via` chain: the enclosing wrappers, outermost first, empty at the top level.

```python
from bash_classify import classify_expression, iter_invocations

for invocation, via in iter_invocations(classify_expression("sudo timeout 5 ls")):
    print(via, invocation.command)
# [] ['sudo']
# ['sudo'] ['timeout']
# ['sudo', 'timeout'] ['ls']
```

`load_rules` and `match_expression` are the same thing from Python:

```python
from bash_classify import load_rules, match_expression

rules = load_rules("blocked-commands.yaml")
result = match_expression('cat > brief.md <<"EOF"\nmentions glab mr note\nEOF', rules)
print(result.matches)         # [] - the heredoc body is data, not a command
print(result.parse_warnings)  # []
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

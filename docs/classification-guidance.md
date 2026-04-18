# Classification Guidance

A practical guide for contributors who want to add or review command definitions in the bash-classify database.

## 1. Purpose

bash-classify is a CLI tool that parses bash expressions, classifies each command against a known-command database, and outputs a structured JSON verdict. It is used as a **Claude Code PreToolUse hook** to auto-allow readonly commands while requiring user confirmation for anything that writes, deletes, or executes arbitrary code.

The command database is the backbone of this system. Each YAML file describes a command's subcommands, options, and their classifications. When a user runs `kubectl get pods`, the database tells bash-classify this is READONLY and safe to auto-allow. When they run `kubectl delete namespace production`, the database tells bash-classify this is DANGEROUS and requires explicit confirmation.

## 2. Classification Levels

### READONLY

No side effects. Safe to auto-allow without user confirmation.

Examples: `ls`, `cat`, `grep`, `kubectl get`, `git status`, `git log`, `docker ps`, `terraform plan`, `curl https://example.com`

### LOCAL_EFFECTS

Modifies local state only (files, git index, local config). No network or external system interaction. Requires user confirmation.

Examples: `git add`, `git commit`, `cp`, `touch`, `mkdir`, `sed -i`, `chmod`

### EXTERNAL_EFFECTS

Creates, modifies, or deletes data beyond the local machine, or interacts with external systems. Requires user confirmation.

Examples: `git push`, `kubectl apply`, `docker build`, `curl -d '...'`, `npm publish`

### DANGEROUS

Destructive, hard to reverse, or executes arbitrary code. Always requires confirmation.

Examples: `rm -rf`, `git push --force`, `kubectl delete`, `eval`, `python`, `sh -c`, `terraform apply`, `docker run`, `git clean`

### UNKNOWN

Command or subcommand not in the database. Treated as requiring confirmation.

### Severity Ordering

```
DANGEROUS > UNKNOWN > EXTERNAL_EFFECTS > LOCAL_EFFECTS > READONLY
```

UNKNOWN is ranked **above EXTERNAL_EFFECTS** because an unrecognized command should not be silently trusted -- it must be reviewed. A known EXTERNAL_EFFECTS command (like `git push`) is predictable; an unknown command could do anything.

The overall classification of a full expression (e.g. a pipeline) is the **maximum severity** across all commands in the expression.

## 3. Database File Format

Each YAML file defines one command (binary). Files live in `src/bash_classify/commands/` and are validated against the JSON Schema at `schemas/command.schema.json`.

### Annotated Example

```yaml
# $schema: ../../../schemas/command.schema.json    # IDE autocomplete support
command: sed                        # (required) binary name
description: "Stream editor"       # (optional) short one-liner
classification: READONLY            # (optional, default READONLY) base classification
strict: false                       # (optional, default true) unrecognized options -> UNKNOWN?
options:                            # options that affect classification
  -i: {overrides: EXTERNAL_EFFECTS}           # -i changes classification to EXTERNAL_EFFECTS
  --in-place: {overrides: EXTERNAL_EFFECTS, aliases: [-i]}
  -e: {takes_value: true}          # -e consumes the next token as its value
  --expression: {takes_value: true, aliases: [-e]}
  -f: {takes_value: true}
  --file: {takes_value: true, aliases: [-f]}
```

### Field Reference

#### Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `command` | string | *(required)* | Binary name (e.g. `kubectl`, `git`, `sed`) |
| `description` | string | -- | Short one-liner describing the tool |
| `classification` | enum | `READONLY` | Base classification when no subcommand matches |
| `strict` | boolean | `true` | If true, unrecognized options yield UNKNOWN |
| `global_options` | map | -- | Options stripped before subcommand matching |
| `options` | map | -- | Options that affect classification |
| `subcommands` | map | -- | Nested subcommand definitions (recursive) |
| `delegates_to` | object | -- | How the command hands off to an inner command |

#### Option fields

| Field | Type | Description |
|-------|------|-------------|
| `takes_value` | boolean | Whether the option consumes the next token as its value |
| `aliases` | list | Alternative names (e.g. `-n` for `--namespace`) |
| `overrides` | enum | When present, override classification to this level |
| `captures_directory` | boolean | The option's value is a working directory (e.g. `git -C`) |
| `delegates_to` | object | This option triggers delegation (e.g. `find -exec`) |

#### The `# $schema:` comment

Add `# $schema: ../../../schemas/command.schema.json` as the first line of every YAML file. This enables autocomplete and validation in IDEs that support JSON Schema for YAML files.

## 4. Classification Philosophy / Decision Guide

### Default to READONLY when:

- The command only reads data and outputs to stdout (`cat`, `ls`, `head`, `tail`)
- The command inspects system state (`ps`, `df`, `top`, `netstat`, `free`)
- The command is a pure filter/transformer (`grep`, `awk`, `sed` without `-i`, `jq`, `sort` without `-o`)
- The command queries a remote system without changing it (`kubectl get`, `curl` without `-d`/`-F`/`-o`, `dig`, `ping`)

### Use EXTERNAL_EFFECTS when:

- The command creates or modifies files (`touch`, `cp`, `mv`, `mkdir`, `tee`)
- The command modifies local state (`git commit`, `git checkout`, `kubectl apply`)
- The command downloads files (`wget`, `curl -o`)
- The command sends data over the network (`curl -d`, `curl -F`)
- The command wraps another command with elevated context (`sudo`, `nice`)
- The command modifies configuration (`git config`, `kubectl config use-context`)

### Use DANGEROUS when:

- The command deletes data that is hard to recover (`rm`, `git clean`, `kubectl delete namespace`)
- The command executes arbitrary code (`eval`, `python`, `sh`, `bash`, `docker run`, `docker exec`)
- The command affects critical system state (`systemctl restart`, `kill`, `reboot`)
- The command can cause widespread damage (`git push --force`, `chmod -R 777`)
- The command modifies infrastructure (`terraform apply`, `terraform destroy`)
- The command aborts an in-progress operation with potential data loss (`git rebase --abort`, `git merge --abort`)

### Use `strict: false` when:

- The command has too many harmless flags to enumerate (`grep`, `find`, `kubectl get`)
- Unknown flags are almost always safe for this command
- You want to avoid false UNKNOWN classifications for common usage

```yaml
# grep has dozens of flags like -r, -n, -l, -i, -v, etc. -- all safe
command: grep
classification: READONLY
strict: false
```

### Use `strict: true` (default) when:

- The command has specific flags that change its behavior significantly
- You want to catch unrecognized options as a safety measure
- The command is sensitive and unknown flags should be reviewed

When in doubt, leave `strict` at the default (`true`). It is safer to have false UNKNOWNs (which prompt the user) than to miss a dangerous flag.

## 5. Subcommand Classification vs Option Overrides

There are two distinct mechanisms for controlling classification — don't confuse them.

### Subcommand classification: independent, no `overrides` keyword

Each subcommand has its **own** `classification` field. It does not inherit from or override the parent — it simply IS the classification for that subcommand. No special keyword is needed.

```yaml
# git.worktree is EXTERNAL_EFFECTS, but git.worktree.list is READONLY
# No "overrides" keyword — list has its own classification
subcommands:
  worktree:
    classification: EXTERNAL_EFFECTS
    subcommands:
      list:
        classification: READONLY    # independent, not an override
      add:
        classification: EXTERNAL_EFFECTS
      remove:
        classification: EXTERNAL_EFFECTS
```

The parent's classification (`EXTERNAL_EFFECTS`) is used only when **no subcommand matches** — e.g., bare `git worktree` or `git worktree unknown-thing`.

### Option overrides: replace the matched subcommand's classification

The `overrides` keyword is for **options** (flags) that change the classification of the command they belong to. Options can change classification in **both directions** — they can elevate or lower it. The `overrides` field **replaces** the base classification entirely; it does not merely elevate.

### Elevating classification

A flag that makes a normally safe command destructive:

```yaml
# git push is EXTERNAL_EFFECTS, but --force makes it DANGEROUS
command: git
subcommands:
  push:
    classification: EXTERNAL_EFFECTS
    options:
      --force: {overrides: DANGEROUS}
      -f: {overrides: DANGEROUS}
      --force-with-lease: {overrides: EXTERNAL_EFFECTS}   # safer force push stays EXTERNAL_EFFECTS
```

```yaml
# sed is READONLY, but -i modifies files in place
command: sed
classification: READONLY
options:
  -i: {overrides: EXTERNAL_EFFECTS}
```

### Lowering classification

A flag that makes a normally writing command safe to auto-allow:

```yaml
# kubectl apply is EXTERNAL_EFFECTS, but --dry-run only prints what would happen
subcommands:
  apply:
    classification: EXTERNAL_EFFECTS
    options:
      --dry-run: {takes_value: true, overrides: READONLY}
```

```yaml
# tar is EXTERNAL_EFFECTS (creates/extracts archives), but -t only lists contents
command: tar
classification: EXTERNAL_EFFECTS
options:
  -t: {overrides: READONLY}
  --list: {overrides: READONLY, aliases: [-t]}
```

```yaml
# git branch is EXTERNAL_EFFECTS (creates branches), but -l only lists them
subcommands:
  branch:
    classification: EXTERNAL_EFFECTS
    options:
      -l: {overrides: READONLY}
      --list: {overrides: READONLY, aliases: [-l]}
      -D: {overrides: DANGEROUS}     # force-delete is dangerous
```

## 6. Delegation

Some commands do not do work themselves -- they delegate to an inner command. bash-classify models this with `delegates_to`, which tells the matcher how to extract the inner command's argv and classify it recursively.

### Pure-wrapper rule of thumb

For commands that are pure passthroughs -- they do nothing themselves beyond running the inner command (e.g. `env`, `xargs`, `mise exec`, `pnpm exec`) -- **omit `classification`**. The missing base defaults to `READONLY`, which is the identity element for severity-max against the delegated inner: the inner command's classification is what surfaces. Writing `classification: READONLY` explicitly on a pure wrapper is misleading -- it reads as "this command is safe" when the real intent is "inherit from whatever I wrap."

Only set a non-`READONLY` base when the wrapper itself contributes risk regardless of the inner (e.g. `sudo` is `EXTERNAL_EFFECTS` because it elevates privileges) or when the wrapper also has a meaningful standalone behavior that isn't READONLY.

### `rest_are_argv`

All remaining positional args (after the wrapper's own options) form the inner command.

**xargs:** `xargs grep -r foo` -- inner command is `["grep", "-r", "foo"]`

```yaml
command: xargs
# classification omitted -- pure passthrough, inherits from inner
delegates_to:
  mode: rest_are_argv
options:
  -I: {takes_value: true}
  -n: {takes_value: true}
  # ... other xargs options
```

**sudo:** `sudo rm -rf /tmp` -- inner command is `["rm", "-rf", "/tmp"]`

```yaml
command: sudo
classification: EXTERNAL_EFFECTS
delegates_to:
  mode: rest_are_argv
  min_classification: EXTERNAL_EFFECTS   # inner command is at least EXTERNAL_EFFECTS
```

**env:** `env FOO=bar BAZ=1 python script.py` -- strips `FOO=bar BAZ=1`, inner command is `["python", "script.py"]`

```yaml
command: env
# classification omitted -- pure passthrough
delegates_to:
  mode: rest_are_argv
  strip_assignments: true     # strip leading KEY=VALUE tokens
```

### `after_separator`

Everything after a separator token forms the inner command.

**kubectl exec:** `kubectl exec -it my-pod -- cat /etc/config` -- inner command is `["cat", "/etc/config"]`

```yaml
subcommands:
  exec:
    classification: DANGEROUS
    delegates_to:
      mode: after_separator
      separator: "--"
```

### `terminated_argv`

Tokens after the flag up to a terminator form the inner command. Placeholder tokens like `{}` are stripped.

**find -exec:** `find . -name "*.tmp" -exec rm -f {} \;` -- inner command is `["rm", "-f"]`

```yaml
command: find
classification: READONLY
strict: false
options:
  -exec:
    overrides: DANGEROUS
    delegates_to:
      mode: terminated_argv
      terminator: ";"
```

Note that `-exec` is defined as an **option** with both `overrides` (to elevate find's classification) and `delegates_to` (to extract and classify the inner command).

### `flag_value_is_expression`

The value of a specific flag is a complete shell expression, parsed from scratch through the bash parser.

**sh -c:** `sh -c "ls /tmp | grep log"` -- the string `ls /tmp | grep log` is parsed as a full expression, producing two inner commands.

```yaml
command: sh
classification: DANGEROUS
delegates_to:
  mode: flag_value_is_expression
  flag: -c
options:
  -c: {takes_value: true}
```

### Delegation fields

| Field | Type | Applies to | Description |
|-------|------|-----------|-------------|
| `mode` | enum | all | One of the four modes above |
| `separator` | string | `after_separator` | Token that separates wrapper args from inner args |
| `terminator` | string | `terminated_argv` | Token that ends the inner argv |
| `flag` | string | `flag_value_is_expression` | Which flag's value to parse as an expression |
| `strip_assignments` | boolean | `rest_are_argv` | Strip leading `KEY=VALUE` tokens before inner command |
| `min_classification` | enum | all | Floor classification for the inner command |

### `min_classification`

Forces the inner command to be classified at least at the given level. sudo uses this to ensure that even `sudo ls` is at least EXTERNAL_EFFECTS -- because running anything under elevated privileges is not a no-op.

## 7. Special Cases

### Commands with non-READONLY base classification

Some commands default to a higher classification when used without a recognized subcommand:

- **kubectl** -- base `EXTERNAL_EFFECTS` (bare `kubectl` without a known subcommand should not be auto-allowed)
- **terraform** -- base `DANGEROUS` (unknown terraform subcommands could modify infrastructure)
- **docker** -- no explicit base classification, so commands like `docker unknown-thing` fall through as UNKNOWN

### Shell builtins hardcoded in the matcher

These cannot be modeled as database entries because they are shell builtins with special semantics:

| Builtin | Classification | Reason |
|---------|---------------|--------|
| `cd`, `pushd`, `popd` | READONLY | Directory navigation only |
| `eval` | DANGEROUS | Arbitrary code execution, argument is unparseable |
| `source`, `.` | DANGEROUS | Executes an external script |
| `exec` (builtin) | DANGEROUS | Replaces the current process |

### Path-qualified commands

Commands invoked with a full path (e.g. `/usr/bin/rm`) are resolved to their basename (`rm`) for database lookup.

### The `# $schema:` comment

The first line `# $schema: ../../../schemas/command.schema.json` is a convention for IDE support. It is not parsed by bash-classify itself but provides autocomplete and validation when editing YAML files in editors that support JSON Schema.

## 8. Risk Levels

Each command also has a risk level (`LOW`, `MEDIUM`, `HIGH`) that defaults based on classification. You only need to set `risk` explicitly in YAML when the default does not fit.

### When to set `risk: LOW`

Use for safe routine operations that should be auto-allowed, even though their classification is above READONLY:

```yaml
# git add only stages files -- safe to auto-allow
subcommands:
  add:
    classification: LOCAL_EFFECTS
    risk: LOW
```

Other good candidates: `git fetch`, `mkdir`, `touch`, code formatters like `ruff format`, `prettier`.

### When to leave the default (`MEDIUM`)

The default `MEDIUM` is appropriate for most `LOCAL_EFFECTS` and `EXTERNAL_EFFECTS` commands. If the command does what its classification says and nothing surprising, don't set `risk` at all.

### When to set `risk: HIGH`

Use when a command is more dangerous than its classification default suggests -- e.g. an `EXTERNAL_EFFECTS` command that is particularly destructive or hard to reverse.

### `DANGEROUS` and `UNKNOWN` are always `HIGH`

Commands classified as `DANGEROUS` or `UNKNOWN` are automatically clamped to `HIGH` risk regardless of any explicit `risk` field. You never need to set `risk` on these.

### Risk on options

Options can override risk the same way they override classification:

```yaml
subcommands:
  apply:
    classification: EXTERNAL_EFFECTS
    options:
      --dry-run: {takes_value: true, overrides: READONLY, risk: LOW}
```

## 9. Subcommand Matching Modes

### `subcommand_mode: hierarchical` (default)

The default mode. Subcommands form a tree, and matching walks the tree greedily. This is correct for most CLI tools where subcommands are hierarchical (e.g. `kubectl rollout status`, `git stash list`).

### `subcommand_mode: match_all`

Use for build tools that accept multiple goals or tasks as positional arguments in any order. Each positional argument is matched independently against the same subcommand dictionary.

```yaml
# Maven accepts multiple lifecycle phases: mvn clean install
command: mvn
classification: LOCAL_EFFECTS
strict: false
subcommand_mode: match_all
subcommands:
  clean:
    classification: LOCAL_EFFECTS
    risk: LOW
  compile:
    classification: LOCAL_EFFECTS
    risk: LOW
  install:
    classification: LOCAL_EFFECTS
    risk: LOW
  deploy:
    classification: EXTERNAL_EFFECTS
```

**When to use `match_all`:**

- Build tools that accept multiple goals/tasks (Maven, Gradle)
- Commands where positional args are independent operations, not hierarchical nesting

**How classification works:**

- The final classification is the maximum severity across all matched goals
- `mvn clean install` → both LOCAL_EFFECTS → final: LOCAL_EFFECTS
- `mvn clean deploy` → LOCAL_EFFECTS + EXTERNAL_EFFECTS → final: EXTERNAL_EFFECTS
- Unrecognized goals (e.g. custom Maven plugin goals like `some-plugin:goal`) fall back to the command's base classification and risk
- Option overrides (e.g. `--dry-run`) still take precedence over goal aggregation

## 10. Temp Path Risk Behavior

When a command writes to a file via output redirects (`>`, `>>`, `2>`, `&>`, `>&`), its risk is normally elevated to at least `MEDIUM`. However, if **all** write targets are under `/tmp` or `/var/tmp`, the risk elevation is skipped and the command stays at `LOW` risk (assuming no other risk elevations apply).

This means `cat > /tmp/foo.txt` is classified as `LOCAL_EFFECTS` with risk `LOW`, while `cat > ~/foo.txt` is classified as `LOCAL_EFFECTS` with risk `MEDIUM`.

The tool also reports `write_paths` and `read_paths` in the output, extracted from redirect operators. These fields are omitted from the JSON output when empty.

## 11. Common Patterns

| Pattern | Example | Classification |
|---------|---------|---------------|
| Pure reader | `cat`, `grep`, `ls` | READONLY |
| Filter with in-place mode | `sed` base, `sed -i` | READONLY / EXTERNAL_EFFECTS |
| File creator/modifier | `cp`, `mv`, `touch` | EXTERNAL_EFFECTS |
| Subcommand-driven | `git`, `kubectl` | Per subcommand |
| Arbitrary code executor | `python`, `sh`, `eval` | DANGEROUS |
| Wrapper/delegator | `sudo`, `xargs`, `env` | Delegation-based |
| Lister with create mode | `git branch`, `git tag` | EXTERNAL_EFFECTS base, `-l` overrides to READONLY |
| Dry-run capable | `make`, `kubectl apply` | EXTERNAL_EFFECTS base, `--dry-run` overrides to READONLY |
| Network tool (read) | `curl`, `ping`, `dig` | READONLY |
| Network tool (write) | `curl -d`, `wget` | EXTERNAL_EFFECTS |
| System admin | `systemctl`, `kill` | DANGEROUS |

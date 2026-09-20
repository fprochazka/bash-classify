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
| `global_options` | map | -- | Options that belong to the binary rather than to one subcommand. Stripped before subcommand matching, and re-checked afterwards, so an entry here **applies at every subcommand depth** -- see [Global options apply at every depth](#global-options-apply-at-every-depth) |
| `options` | map | -- | Options that affect classification |
| `subcommands` | map | -- | Nested subcommand definitions (recursive) |
| `delegates_to` | object | -- | How the command hands off to an inner command |

#### Subcommand fields

A subcommand takes the same fields as the top level, minus `command`, `description` and `global_options`, plus:

| Field | Type | Description |
|-------|------|-------------|
| `aliases` | list | Alternative names for this subcommand (e.g. `pipe` and `pipeline` for `glab ci`) |

An alias is another name for the same definition, not a copy of it: `glab pipeline view` classifies exactly as `glab ci view` and is reported as `["glab", "ci", "view"]`, while `argv` keeps the word that was typed. Declare aliases only for names the tool itself accepts (`glab ci --help` lists `pipe` and `pipeline`), and never a name a sibling subcommand already uses — that is rejected when the file loads.

```yaml
subcommands:
  ci:
    aliases: [pipe, pipeline]
    subcommands:
      list:
        classification: READONLY
```

#### Option fields

| Field | Type | Description |
|-------|------|-------------|
| `takes_value` | boolean | Whether the option consumes the next token as its value |
| `aliases` | list | Alternative names (e.g. `-n` for `--namespace`) |
| `overrides` | enum | When present, override classification to this level |
| `captures_directory` | boolean | The option's value is a directory the command is pointed at: a working directory (`git -C`) or an extraction destination (`tar -C`, `unzip -d`). It lands in the `directories` of the invocation that carries the option, wrapped or not. The expression-level `directories` picks it up only for a top-level invocation. |
| `names_output_path` | boolean | The option's value is a path the command writes (`curl -o`, `sort -o`). It lands in `write_paths`. |
| `before_subcommand_only` | boolean | `global_options` only: the tool honours this option ahead of its subcommand and not after one (`docker -v` is `--version`; `docker compose down -v` is `--volumes`). |
| `delegates_to` | object | This option triggers delegation (e.g. `find -exec`) |

##### Marking an option as an output path

`names_output_path` answers one question: does the tool's own documentation say this option's value names a file it writes? Check the man page before you set it, and apply three rules.

1. A read is not a write. `curl -T file` uploads the named file to a server and writes nothing locally, so it stays unmarked.
2. The answer has to hold in every mode of the command. `tar -f` writes the archive under `-c` and reads it under `-x`, and one option cannot be conditioned on another, so it stays unmarked.
3. A destination named by a positional is out of reach. `cp a b`, `tee out.txt`, `dd of=X` and the prefix of `split` are not options, and nothing in the database describes them.

A consumer uses the field to tell a write to a credential from a mention of one, so a wrong mark is worse than a missing one. When in doubt, leave it off.

### Global options apply at every depth

`global_options` is stripped ahead of subcommand matching, and the leftovers are re-checked against it afterwards so that `kubectl apply --help` works. Both halves mean the same thing: **an entry in `global_options` is claimed to be valid, and to mean the same thing, at every subcommand depth of the file.** Before adding one -- especially an `overrides` -- run it against the real binary *with a subcommand*, not just bare. Bare is the spelling that always works and it proves nothing.

A short flag whose long spelling differs per subcommand is the trap, and `-v` is almost always that flag:

```
docker -v                 ->  --version, prints and exits
docker compose down -v    ->  --volumes, removes the named volumes
```

Declared as a plain global, `overrides: READONLY` on `-v` turns the second line into READONLY/LOW, which the bundled hook auto-approves. The same shape caught `git push -v` and `git commit -v` (`--verbose`, and the push and the commit both happen), `pip install -V` (silently ignored, and the install happens), and `apt upgrade -v`.

Three answers, in order of preference:

1. **The flag really is universal.** `--help` usually is, and `-h` often is -- but not always: `-h` is human-readable for `du` and `df`, no-dereference for `chown`, `chgrp` and `ln`, and a Click-based CLI answers `No such option: -h` at every depth. Declare it only after seeing it work at depth.
2. **The flag is honoured only ahead of the subcommand.** Mark it `before_subcommand_only: true`. It is then stripped as a global on `docker -v` and ignored on `docker compose down -v`, which is exactly what the tool does. This is what `git`, `docker`, `mise`, `uv`, `cargo`, `pip`, `pip3`, `pipx` and `brew` use for their version flags. `apt` is the counter-example: it honours both spellings at every depth and acts on neither, so it needs no marker -- and where one of its subcommands takes its own `-v`, that subcommand declares it, which is the third answer below applied in reverse.
3. **The flag does not exist.** Do not declare it. A declaration that does not correspond to a real flag is a free `READONLY` on every command that happens to carry that token.

A *subcommand's* own `options:` need a different kind of care, not less of it. They reach only that subcommand, so the depth question does not arise -- but an `overrides` there still applies wherever the flag appears in the invocation, operands included, and it is not subject to the operand rule below. `git branch` declares `-v` as `overrides: READONLY` because `git branch -v` lists; `git branch <name> -v` creates the branch and reads READONLY all the same. Before writing `overrides: READONLY` on a subcommand's flag, ask whether the same flag means the same thing in that subcommand's *other* mode.

**The operand rule.** A `global_options` override that would make the command look *safer* is ignored once the invocation has an operand, because an operand means the binary is dispatching and the token may not be its own -- `docker run alpine sh -c '<script>' --help` hands the `--help` to the container and the script still runs. An override that would make it look *more dangerous* is applied wherever it appears; guessing the token belongs to the operand is the cautious reading only in one direction. This is why `apt install foo --version` is HIGH while `apt --version` is LOW, and why a `--unmasked` that prints plaintext tokens survives an operand.

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

All remaining positional args (after the wrapper's own options) form the inner command. One leading `--` is the
wrapper's own end-of-options marker rather than the program word, and is skipped: `sudo -- rm -rf /` delegates to
`rm`, not to `--`.

That holds only while the `--` comes before any operand of the wrapper itself, because that is the only place the
wrapper's own option parser is still reading. `env` stops at the first assignment and `timeout` at the duration, so
in `env FOO=bar -- ls` and `timeout 5 -- ls` the `--` really is the program word and both really do fail with "No
such file or directory" -- the database says `UNKNOWN` because the shell says 127. `timeout -- 5 ls`, which a real
`timeout` accepts, skips the marker and then the duration, and resolves to `ls`. Only one marker is skipped: POSIX
makes the second `--` in `sudo -- -- ls` the program name.

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

### `args_are_expression`

Every argument is joined with single spaces and the result is parsed as a complete shell expression. This is what
`eval` does: it concatenates its arguments and runs the concatenation as shell source, so `eval ls -la` and
`eval "ls -la"` are the same command. Unlike `flag_value_is_expression`, no flag selects the expression -- every
token after the binary is part of it, so a command using this mode must not declare options of its own.

**eval:** `eval "git push --force"` -- the string `git push --force` is parsed as a full expression, producing one
inner command.

```yaml
command: eval
classification: DANGEROUS
strict: false
delegates_to:
  mode: args_are_expression
  min_classification: DANGEROUS   # eval stays DANGEROUS even when the inner is READONLY
```

The `min_classification` floor is not optional here. Command-level delegation erases the wrapper's own base
classification once it resolves an inner command, so without the floor `eval "ls"` would classify READONLY.

### Delegation fields

| Field | Type | Applies to | Description |
|-------|------|-----------|-------------|
| `mode` | enum | all | One of the modes above |
| `separator` | string | `after_separator` | Token that separates wrapper args from inner args |
| `terminator` | string | `terminated_argv` | Token that ends the inner argv |
| `flag` | string | `flag_value_is_expression` | Which flag's value to parse as an expression |
| `skip_leading_positionals` | integer | `rest_are_argv` | Positional tokens belonging to the wrapper itself before the inner command starts (e.g. `timeout DURATION COMMAND...` uses `1`) |
| `strip_assignments` | boolean | `rest_are_argv` | Strip leading `KEY=VALUE` tokens before inner command |
| `min_classification` | enum | all | Floor classification for the inner command |

### `min_classification`

Forces the inner command to be classified at least at the given level. sudo uses this to ensure that even `sudo ls` is at least EXTERNAL_EFFECTS -- because running anything under elevated privileges is not a no-op. `eval` and `exec` use it the same way, with a `DANGEROUS` floor.

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
| `[`, `[[`, `test` | READONLY | Condition evaluation, no side effects |
| `source`, `.` | DANGEROUS | Executes an external script, whose contents are never visible |

`eval` and `exec` used to be in this list. They are database entries now -- `commands/eval.yaml`
delegates via `args_are_expression`, `commands/exec.yaml` via `rest_are_argv`, both with
`min_classification: DANGEROUS`. Modelling them in YAML exposes the inner command instead of
hiding it, and the floor is what keeps them DANGEROUS even when the inner command is READONLY.
Reach for a hardcoded builtin only when the command's argument is genuinely not a command line.

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

When a command writes to a file via an output redirect, its risk is normally elevated to at least `MEDIUM`. If **all** write targets are under `/tmp` or `/var/tmp`, the elevation is skipped and the command stays at `LOW` risk, as long as nothing else elevates it. Which operators count as a write is given in [SPEC.md](../SPEC.md#redirect-classification).

This means `cat > /tmp/foo.txt` is classified as `LOCAL_EFFECTS` with risk `LOW`, while `cat > ~/foo.txt` is classified as `LOCAL_EFFECTS` with risk `MEDIUM`.

The tool also reports `write_paths` and `read_paths` in the output. `read_paths` comes from input redirects. `write_paths` holds the targets of output redirects and the values of options marked `names_output_path`. Both fields are omitted from the JSON output when empty, and neither is a complete account of what the command touches: a destination named by a plain positional is in neither.

## 11. Sensitive Paths

Credential paths are **not** part of the command database, and you should not try to express them there. A command definition says what a command does; it never says which of its arguments are paths, let alone which of those hold secrets. The two questions are separate and are answered in separate files.

The denylist lives in `src/bash_classify/sensitive-paths.yaml`, validated against `schemas/sensitive-paths.schema.json`. A token that matches one of its rules floors the command's risk at `HIGH` and leaves its classification alone, so `cat ~/.ssh/id_rsa` stays `READONLY` and stops being auto-approved.

Two consequences when you write a command definition:

- Do not lower a command's risk to work around a sensitive-path hit. The hit is a floor and is applied after your definition; a `risk: LOW` on `cat` does not undo it, and the hook prompts either way.
- Do not add a rule to the denylist for a path that is merely uninteresting to read. Every false positive is a reason for somebody to switch the whole gate off. A rule belongs there when the file holds a credential. That is why `~/.aws/credentials` and `~/.config/gh/hosts.yml` are on the list, while `~/.aws/config`, `.git/config` and `~/.config/gh/config.yml` are not.

Add a rule when a tool you define keeps its credentials somewhere the bundled rules miss. Match whole segments, keep the segments literal, and give the rule a name that says what the secret is:

```yaml
rules:
  - name: acme-cli
    paths:
      - .acme/credentials
      - .config/acme/token
```

See the "Sensitive Path Detection" section of [SPEC.md](../SPEC.md) for how tokens are read and what the feature deliberately misses.

## 12. Common Patterns

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

# bash-classify: Product Specification

A CLI tool that parses bash expressions into an AST, classifies each command against a known-command database, and outputs a structured JSON verdict.

## Interface

### Simple pipeline

```
$ echo 'kubectl --context=prod get pods -n kube-system | grep Running' | bash-classify
```

```json
{
  "expression": "kubectl --context=prod get pods -n kube-system | grep Running",
  "classification": "READONLY",
  "directories": [],
  "commands": [
    {
      "command": ["kubectl", "get", "pods"],
      "argv": ["kubectl", "--context=prod", "get", "pods", "-n", "kube-system"],
      "classification": "READONLY",
      "matched_rule": "kubectl.get",
      "ignored_options": ["--context=prod"],
      "remaining_options": ["-n", "kube-system"],
      "inner_commands": []
    },
    {
      "command": ["grep"],
      "argv": ["grep", "Running"],
      "classification": "READONLY",
      "matched_rule": "grep",
      "inner_commands": []
    }
  ]
}
```

### Nested delegation (xargs)

```
$ echo 'find /tmp -name "*.log" | xargs -I {} rm {}' | bash-classify
```

```json
{
  "expression": "find /tmp -name \"*.log\" | xargs -I {} rm {}",
  "classification": "UNKNOWN",
  "directories": ["/tmp"],
  "commands": [
    {
      "command": ["find"],
      "argv": ["find", "/tmp", "-name", "*.log"],
      "classification": "READONLY",
      "matched_rule": "find",
      "inner_commands": []
    },
    {
      "command": ["xargs"],
      "argv": ["xargs", "-I", "{}", "rm", "{}"],
      "classification": "UNKNOWN",
      "matched_rule": "xargs",
      "inner_commands": [
        {
          "delegation_mode": "rest_are_argv",
          "delegation_source": "xargs",
          "command": ["rm"],
          "argv": ["rm", "{}"],
          "classification": "UNKNOWN",
          "matched_rule": null,
          "inner_commands": []
        }
      ]
    }
  ]
}
```

### Nested delegation (find -exec)

```
$ echo 'find . -name "*.tmp" -exec rm -f {} \;' | bash-classify
```

```json
{
  "expression": "find . -name \"*.tmp\" -exec rm -f {} \\;",
  "classification": "DANGEROUS",
  "directories": ["."],
  "commands": [
    {
      "command": ["find"],
      "argv": ["find", ".", "-name", "*.tmp", "-exec", "rm", "-f", "{}", ";"],
      "classification": "DANGEROUS",
      "matched_rule": "find",
      "inner_commands": [
        {
          "delegation_mode": "terminated_argv",
          "delegation_source": "-exec",
          "command": ["rm"],
          "argv": ["rm", "-f"],
          "classification": "DANGEROUS",
          "matched_rule": "rm",
          "inner_commands": []
        }
      ]
    }
  ]
}
```

### Nested delegation (kubectl exec)

```
$ echo 'kubectl exec -it my-pod -- cat /etc/config' | bash-classify
```

```json
{
  "expression": "kubectl exec -it my-pod -- cat /etc/config",
  "classification": "DANGEROUS",
  "directories": [],
  "commands": [
    {
      "command": ["kubectl", "exec"],
      "argv": ["kubectl", "exec", "-it", "my-pod", "--", "cat", "/etc/config"],
      "classification": "DANGEROUS",
      "matched_rule": "kubectl.exec",
      "inner_commands": [
        {
          "delegation_mode": "after_separator",
          "delegation_source": "--",
          "command": ["cat"],
          "argv": ["cat", "/etc/config"],
          "classification": "READONLY",
          "matched_rule": "cat",
          "inner_commands": []
        }
      ]
    }
  ]
}
```

### Nested delegation (sh -c with full expression parsing)

```
$ echo 'sh -c "ls /tmp | grep log"' | bash-classify
```

```json
{
  "expression": "sh -c \"ls /tmp | grep log\"",
  "classification": "DANGEROUS",
  "directories": ["/tmp"],
  "commands": [
    {
      "command": ["sh"],
      "argv": ["sh", "-c", "ls /tmp | grep log"],
      "classification": "DANGEROUS",
      "matched_rule": "sh",
      "inner_commands": [
        {
          "delegation_mode": "flag_value_is_expression",
          "delegation_source": "-c",
          "command": ["ls"],
          "argv": ["ls", "/tmp"],
          "classification": "READONLY",
          "matched_rule": "ls",
          "inner_commands": []
        },
        {
          "delegation_mode": "flag_value_is_expression",
          "delegation_source": "-c",
          "command": ["grep"],
          "argv": ["grep", "log"],
          "classification": "READONLY",
          "matched_rule": "grep",
          "inner_commands": []
        }
      ]
    }
  ]
}
```

### Exit codes

- `0` — successfully classified
- `1` — parse error (invalid bash syntax)
- `2` — internal error

### Classification levels

| Level | Meaning |
|---|---|
| `READONLY` | Only reads data, no side effects |
| `LOCAL_EFFECTS` | Modifies local files or state only |
| `EXTERNAL_EFFECTS` | Interacts with external systems or network |
| `DANGEROUS` | Destructive, hard to reverse, or affects critical systems |
| `UNKNOWN` | Command or subcommand not in database |

### Composite classification

The overall `classification` of a full expression is the **maximum severity** across all commands in the expression:

```
DANGEROUS > UNKNOWN > EXTERNAL_EFFECTS > LOCAL_EFFECTS > READONLY
```

`UNKNOWN` is ranked above `EXTERNAL_EFFECTS` because an unrecognized command should not be silently trusted — it must be reviewed.

## Bash Parsing

Use **tree-sitter-bash** (Python bindings via `tree-sitter` + `tree-sitter-bash`) to parse the input into a concrete syntax tree.

### Extracted structure

The parser walks the CST and extracts a list of `CommandInvocation` objects, each with:

- `argv: list[str]` — the full token list (command name + args)
- `redirects: list[Redirect]` — each with `op` (`>`, `>>`, `<`, `>&`, `2>`, etc.) and `target` (filename or fd)
- `position_in_pipeline: int` — 0-indexed position in a pipeline
- `pipeline_length: int` — total commands in the pipeline
- `context: "toplevel" | "subshell" | "command_substitution" | "process_substitution"`
- `operator_before: str | None` — `&&`, `||`, `;`, or `None` (for first command / pipe members)

### Constructs to handle

| Construct | Handling |
|---|---|
| Pipelines `a \| b \| c` | Each command extracted separately |
| Logical operators `a && b`, `a \|\| b` | Each command extracted separately |
| Semicolons `a; b` | Each command extracted separately |
| Command substitution `$(cmd)` | Inner command extracted recursively |
| Process substitution `<(cmd)` / `>(cmd)` | Inner command extracted recursively |
| Subshells `(cmd)` | Inner command extracted recursively |
| Heredocs `<<EOF` | Content captured but not parsed as commands |
| Variable assignments `X=1 cmd` | Prefix assignments stripped, `cmd` extracted |
| Backgrounding `cmd &` | Classified as EXTERNAL_EFFECTS (side effect: background process) |

### Constructs that force DANGEROUS

| Construct | Reason |
|---|---|
| `eval "..."` | Arbitrary code execution, unparseable |
| `sh -c "..."` / `bash -c "..."` | Nested shell, unparseable |
| `source file` / `. file` | Executes external script |
| Unquoted variable expansion in command position (`$CMD args`) | Command identity unknown at parse time |

## Command Matching Algorithm

This is the core of the tool. Given an `argv` like `["kubectl", "--context=prod", "get", "pods", "-n", "kube-system"]`, the matcher must:

1. **Look up the binary** (`kubectl`) in the database
2. **Separate global options** from the rest of `argv`, using the database definition of which options are global and whether they take a value
3. **Match the subcommand chain** from the remaining tokens (e.g. `get` → resolve to `kubectl.get`)
4. **Classify remaining options** against the matched subcommand's option definitions
5. **Determine the final classification** based on subcommand default + any option overrides

### Matching detail

```
argv: ["kubectl", "--context=prod", "get", "pods", "-n", "kube-system"]

Step 1: binary lookup → found "kubectl" in database
Step 2: strip global options
  - "--context=prod" matches global option "--context" (takes_value, form: --opt=val)
  - remaining: ["get", "pods", "-n", "kube-system"]
Step 3: subcommand matching
  - "get" matches subcommand "get" under kubectl
  - remaining: ["pods", "-n", "kube-system"]
Step 4: option classification
  - "-n" is a known option of "kubectl.get" (alias for --namespace, takes value)
  - "pods" and "kube-system" are positional args (not classified)
Step 5: classification
  - "kubectl.get" base classification: READONLY
  - no option overrides → final: READONLY
```

### Option parsing rules

The matcher must handle standard option formats:

- `--flag` (boolean long option)
- `--key=value` (long option with value, joined)
- `--key value` (long option with value, separated)
- `-f` (short boolean option)
- `-f value` (short option with value, separated)
- `-fvalue` (short option with value, joined — e.g. `-n5`)
- `-abc` (combined short boolean options — e.g. `-rf` = `-r -f`)
- `--` (end of options, everything after is positional)

The database defines which options take values, so the parser knows whether `-n kube-system` consumes one or two tokens.

### Unrecognized options

If the matched subcommand has `strict: true` (default), any unrecognized option makes the command `UNKNOWN`. If `strict: false`, unrecognized options are ignored (useful for commands with too many harmless flags to enumerate).

## Command Database Format

YAML files, one per command or command family. Loaded from a `commands/` directory.

### Example: `commands/kubectl.yaml`

```yaml
command: kubectl
global_options:
  --context: {takes_value: true}
  --kubeconfig: {takes_value: true}
  --namespace: {takes_value: true, aliases: [-n]}
  --cluster: {takes_value: true}
  --server: {takes_value: true, aliases: [-s]}
  --token: {takes_value: true}
  --as: {takes_value: true}
  --as-group: {takes_value: true}
  --certificate-authority: {takes_value: true}
  --client-certificate: {takes_value: true}
  --client-key: {takes_value: true}
  --insecure-skip-tls-verify: {}
  --tls-server-name: {takes_value: true}
  --v: {takes_value: true}
  --request-timeout: {takes_value: true}

subcommands:
  get:
    classification: READONLY
    strict: false  # too many resource-specific flags to enumerate

  describe:
    classification: READONLY
    strict: false

  logs:
    classification: READONLY
    strict: false

  top:
    classification: READONLY

  api-resources:
    classification: READONLY

  api-versions:
    classification: READONLY

  explain:
    classification: READONLY

  auth:
    subcommands:
      can-i:
        classification: READONLY
      reconcile:
        classification: EXTERNAL_EFFECTS

  apply:
    classification: EXTERNAL_EFFECTS
    options:
      --dry-run: {overrides: READONLY}

  create:
    classification: EXTERNAL_EFFECTS

  delete:
    classification: DANGEROUS
    options:
      --dry-run: {overrides: READONLY}

  edit:
    classification: EXTERNAL_EFFECTS

  patch:
    classification: EXTERNAL_EFFECTS

  scale:
    classification: EXTERNAL_EFFECTS

  rollout:
    subcommands:
      status:
        classification: READONLY
      history:
        classification: READONLY
      restart:
        classification: EXTERNAL_EFFECTS
      undo:
        classification: DANGEROUS
      pause:
        classification: EXTERNAL_EFFECTS
      resume:
        classification: EXTERNAL_EFFECTS

  exec:
    classification: DANGEROUS

  port-forward:
    classification: EXTERNAL_EFFECTS

  cp:
    classification: EXTERNAL_EFFECTS

  drain:
    classification: DANGEROUS

  cordon:
    classification: EXTERNAL_EFFECTS

  uncordon:
    classification: EXTERNAL_EFFECTS

  taint:
    classification: EXTERNAL_EFFECTS

  label:
    classification: EXTERNAL_EFFECTS

  annotate:
    classification: EXTERNAL_EFFECTS

  config:
    subcommands:
      view:
        classification: READONLY
      get-contexts:
        classification: READONLY
      current-context:
        classification: READONLY
      use-context:
        classification: EXTERNAL_EFFECTS
      set:
        classification: EXTERNAL_EFFECTS
      set-context:
        classification: EXTERNAL_EFFECTS
      set-cluster:
        classification: EXTERNAL_EFFECTS
      set-credentials:
        classification: EXTERNAL_EFFECTS
      delete-context:
        classification: DANGEROUS
      delete-cluster:
        classification: DANGEROUS
```

### Example: `commands/git.yaml`

```yaml
command: git
global_options:
  -C: {takes_value: true, captures_directory: true}
  --git-dir: {takes_value: true}
  --work-tree: {takes_value: true}
  --bare: {}
  --no-pager: {}
  --no-replace-objects: {}
  -c: {takes_value: true}  # config override, not directory
  --exec-path: {takes_value: true}

subcommands:
  status:
    classification: READONLY
  log:
    classification: READONLY
    strict: false
  show:
    classification: READONLY
    strict: false
  diff:
    classification: READONLY
    strict: false
  branch:
    classification: READONLY
    options:
      -d: {overrides: EXTERNAL_EFFECTS}
      -D: {overrides: DANGEROUS}
      --delete: {overrides: EXTERNAL_EFFECTS}
      --move: {overrides: EXTERNAL_EFFECTS}
      --copy: {overrides: EXTERNAL_EFFECTS}
      --edit-description: {overrides: EXTERNAL_EFFECTS}
      --set-upstream-to: {overrides: EXTERNAL_EFFECTS, takes_value: true}
      --unset-upstream: {overrides: EXTERNAL_EFFECTS}
  remote:
    classification: READONLY
    subcommands:
      add:
        classification: EXTERNAL_EFFECTS
      remove:
        classification: EXTERNAL_EFFECTS
      rename:
        classification: EXTERNAL_EFFECTS
      set-url:
        classification: EXTERNAL_EFFECTS
      prune:
        classification: EXTERNAL_EFFECTS
  tag:
    classification: READONLY
    options:
      -d: {overrides: EXTERNAL_EFFECTS}
      --delete: {overrides: EXTERNAL_EFFECTS}
      -a: {overrides: EXTERNAL_EFFECTS}
      -s: {overrides: EXTERNAL_EFFECTS}
  blame:
    classification: READONLY
  shortlog:
    classification: READONLY
  reflog:
    classification: READONLY
  rev-parse:
    classification: READONLY
  ls-files:
    classification: READONLY
  ls-remote:
    classification: READONLY
  ls-tree:
    classification: READONLY
  cat-file:
    classification: READONLY
  for-each-ref:
    classification: READONLY

  add:
    classification: EXTERNAL_EFFECTS
  commit:
    classification: EXTERNAL_EFFECTS
  merge:
    classification: EXTERNAL_EFFECTS
    options:
      --abort: {overrides: DANGEROUS}
  rebase:
    classification: EXTERNAL_EFFECTS
    options:
      --abort: {overrides: DANGEROUS}
  cherry-pick:
    classification: EXTERNAL_EFFECTS
    options:
      --abort: {overrides: DANGEROUS}

  push:
    classification: EXTERNAL_EFFECTS
    options:
      --force: {overrides: DANGEROUS}
      -f: {overrides: DANGEROUS}
      --force-with-lease: {overrides: EXTERNAL_EFFECTS}
      --delete: {overrides: DANGEROUS}

  pull:
    classification: EXTERNAL_EFFECTS

  fetch:
    classification: EXTERNAL_EFFECTS
    options:
      --prune: {overrides: EXTERNAL_EFFECTS}

  checkout:
    classification: EXTERNAL_EFFECTS

  switch:
    classification: EXTERNAL_EFFECTS

  restore:
    classification: EXTERNAL_EFFECTS

  stash:
    classification: EXTERNAL_EFFECTS
    subcommands:
      list:
        classification: READONLY
      show:
        classification: READONLY
      drop:
        classification: DANGEROUS
      clear:
        classification: DANGEROUS

  reset:
    classification: EXTERNAL_EFFECTS
    options:
      --hard: {overrides: DANGEROUS}

  revert:
    classification: EXTERNAL_EFFECTS

  clean:
    classification: DANGEROUS

  rm:
    classification: EXTERNAL_EFFECTS
    options:
      -r: {overrides: DANGEROUS}
```

### Example: `commands/find.yaml`

```yaml
command: find
classification: READONLY
strict: false  # find has too many predicates to enumerate
options:
  -delete: {overrides: DANGEROUS}
  -exec:
    delegates_to:
      mode: terminated_argv
      terminator: ";"  # tokens between -exec and \; are the inner command
  -execdir:
    delegates_to:
      mode: terminated_argv
      terminator: ";"
  -ok:
    delegates_to:
      mode: terminated_argv
      terminator: ";"
  -okdir:
    delegates_to:
      mode: terminated_argv
      terminator: ";"
```

### Example: `commands/xargs.yaml`

```yaml
command: xargs
classification: UNKNOWN  # classification depends entirely on the inner command
delegates_to:
  mode: rest_are_argv    # all remaining positional args form the inner command
options:
  -I: {takes_value: true}
  --replace: {takes_value: true, aliases: [-I]}
  -L: {takes_value: true}
  --max-lines: {takes_value: true, aliases: [-L]}
  -n: {takes_value: true}
  --max-args: {takes_value: true, aliases: [-n]}
  -P: {takes_value: true}
  --max-procs: {takes_value: true, aliases: [-P]}
  -d: {takes_value: true}
  --delimiter: {takes_value: true, aliases: [-d]}
  -0: {}
  --null: {}
  --no-run-if-empty: {}
  -r: {}
  -t: {}
  --verbose: {}
  -p: {}
  --interactive: {}
```

### Example: `commands/env.yaml`

```yaml
command: env
classification: READONLY
delegates_to:
  mode: rest_are_argv     # after stripping env's own options and VAR=val assignments
  strip_assignments: true  # strip leading KEY=VALUE tokens before the inner command
options:
  -i: {}
  --ignore-environment: {}
  -u: {takes_value: true}
  --unset: {takes_value: true, aliases: [-u]}
  -C: {takes_value: true, captures_directory: true}
  --chdir: {takes_value: true, captures_directory: true, aliases: [-C]}
```

### Example: `commands/sudo.yaml`

```yaml
command: sudo
classification: EXTERNAL_EFFECTS  # sudo itself elevates privileges
delegates_to:
  mode: rest_are_argv
  min_classification: EXTERNAL_EFFECTS  # inner command is at least EXTERNAL_EFFECTS regardless of its own classification
options:
  -u: {takes_value: true}
  --user: {takes_value: true, aliases: [-u]}
  -g: {takes_value: true}
  --group: {takes_value: true, aliases: [-g]}
  -H: {}
  --set-home: {}
  -E: {}
  --preserve-env: {}
  -n: {}
  --non-interactive: {}
  -S: {}
  --stdin: {}
  -k: {}
  --reset-timestamp: {}
```

### Example: `commands/kubectl.yaml` (exec subcommand with `--`)

```yaml
# ... (global_options and other subcommands as above)

subcommands:
  exec:
    classification: DANGEROUS
    delegates_to:
      mode: after_separator
      separator: "--"  # everything after -- is the inner command
    options:
      -it: {}  # combined short flags
      -i: {}
      --stdin: {aliases: [-i]}
      -t: {}
      --tty: {aliases: [-t]}
      -c: {takes_value: true}
      --container: {takes_value: true, aliases: [-c]}
      -n: {takes_value: true}
      --namespace: {takes_value: true, aliases: [-n]}
```

### Example: `commands/sh.yaml`

```yaml
command: sh
classification: DANGEROUS  # by default, running a shell is dangerous
delegates_to:
  mode: flag_value_is_expression
  flag: -c                     # the value of -c is a full shell expression to parse recursively
options:
  -c: {takes_value: true}
  -e: {}
  -x: {}
  -i: {}
```

The same pattern applies to `bash.yaml` and `zsh.yaml`.

### Delegation modes reference

The `delegates_to` field defines how a command (or option like `find -exec`) hands off execution to an inner command. The inner command is classified recursively and appears as `inner_commands` in the output.

| Mode | How the inner argv is extracted | Example |
|---|---|---|
| `rest_are_argv` | All remaining positional args after the wrapper's own options are consumed. The first positional arg is the binary, the rest are its arguments. | `xargs grep -r foo` → inner: `["grep", "-r", "foo"]` |
| `after_separator` | Everything after the `separator` token forms the inner argv. | `kubectl exec pod -- ls -la` → inner: `["ls", "-la"]` |
| `terminated_argv` | Tokens after the flag up to `terminator` form the inner argv. `{}` tokens are stripped (they are `find` placeholders). | `find . -exec rm {} \;` → inner: `["rm"]` |
| `flag_value_is_expression` | The value of the specified `flag` is a complete shell expression string, parsed from scratch through the bash parser (not just tokenized as argv). | `sh -c "ls \| grep foo"` → inner expression: `ls \| grep foo` (two piped commands) |

#### Delegation fields

| Field | Type | Description |
|---|---|---|
| `mode` | `enum` | One of the modes above |
| `separator` | `string` | For `after_separator`: the token that separates wrapper args from inner args |
| `terminator` | `string` | For `terminated_argv`: the token that ends the inner argv |
| `flag` | `string` | For `flag_value_is_expression`: which flag's value to parse |
| `strip_assignments` | `bool` | For `rest_are_argv`: strip leading `KEY=VALUE` tokens before the inner command |
| `min_classification` | `enum` | Floor classification for the inner command (e.g. `sudo` forces at least `EXTERNAL_EFFECTS`) |

### Database field reference

#### Command level

| Field | Type | Description |
|---|---|---|
| `command` | `string` | Binary name |
| `classification` | `enum` | Default classification for the command (when no subcommand matched) |
| `global_options` | `map` | Options that appear before subcommands and are stripped before matching |
| `subcommands` | `map` | Nested subcommand definitions (recursive structure) |
| `options` | `map` | Options that affect classification of this command/subcommand |
| `strict` | `bool` | If `true` (default), unrecognized options yield `UNKNOWN` |
| `delegates_to` | `object` | How this command delegates execution to an inner command (see delegation modes) |

#### Option level

| Field | Type | Description |
|---|---|---|
| `takes_value` | `bool` | Whether the option consumes the next token as its value |
| `aliases` | `list[str]` | Alternative names for this option (e.g. `-n` for `--namespace`) |
| `overrides` | `enum` | When this option is present, override the classification to this level |
| `captures_directory` | `bool` | The value of this option is a working directory (e.g. `git -C`) |
| `delegates_to` | `object` | This option's value(s) form a delegated inner command (e.g. `find -exec`) |

## Redirect Classification

Output redirects affect the overall classification:

| Redirect | Effect |
|---|---|
| `> file` | Elevates to at least `EXTERNAL_EFFECTS` |
| `>> file` | Elevates to at least `EXTERNAL_EFFECTS` |
| `> /dev/null` | No effect (discarding output is not a write) |
| `2> file` / `2>> file` | Elevates to at least `EXTERNAL_EFFECTS` (unless `/dev/null`) |
| `&> file` | Elevates to at least `EXTERNAL_EFFECTS` (unless `/dev/null`) |
| `< file` | No effect (input redirect is reading) |
| `\| tee file` | `tee` is classified as `EXTERNAL_EFFECTS` via its own database entry |

## Directory Detection

The tool extracts working directories from:

| Source | Example |
|---|---|
| `cd dir` / `pushd dir` / `popd` | Explicit directory changes |
| Global options with `captures_directory: true` | `git -C /path`, `make -C /path` |
| Well-known commands | `ls /path`, `find /path`, `cat /path/file` (dirname) |

Directories are reported as-is (not resolved) since variable expansion may be involved.

## Special-cased Commands

Most delegation behavior is expressed in the database via `delegates_to`. Only shell builtins that cannot be modeled as regular commands need hardcoded handling:

| Command | Special handling |
|---|---|
| `cd`, `pushd`, `popd` | Directory tracking; classified as `READONLY` |
| `eval` | Always `DANGEROUS` — argument is arbitrary code, no delegation possible |
| `source`, `.` | Always `DANGEROUS` — executes external script |
| `exec` (builtin) | Always `DANGEROUS` — replaces the current process |

Everything else (`sudo`, `env`, `xargs`, `sh -c`, `nice`, `nohup`, `timeout`, `time`, `find -exec`, `kubectl exec --`, etc.) is handled via `delegates_to` in the database — no special code needed.

## Implementation Language

Python 3.12+. Dependencies:

- `tree-sitter` + `tree-sitter-bash` — bash parsing
- `pyyaml` — database loading
- No other runtime dependencies

## Output Schema

The `commands` list is recursive — any command entry can contain `inner_commands` when the command delegates execution to another command (via `delegates_to` in the database).

```json
{
  "expression": "string — the original input",
  "classification": "READONLY | LOCAL_EFFECTS | EXTERNAL_EFFECTS | DANGEROUS | UNKNOWN",
  "directories": ["string — detected directories"],
  "commands": [
    {
      "command": ["string — binary + subcommand chain (without inner command tokens)"],
      "argv": ["string — full original argv for this command"],
      "classification": "READONLY | LOCAL_EFFECTS | EXTERNAL_EFFECTS | DANGEROUS | UNKNOWN",
      "matched_rule": "string — dotted path in database, or null",
      "ignored_options": ["string — global options that were stripped"],
      "remaining_options": ["string — options that were not in database"],
      "classification_reason": "string — why this classification was chosen",
      "overriding_option": "string | null — the option that elevated classification",
      "inner_commands": [
        {
          "delegation_mode": "string — how this inner command was extracted",
          "delegation_source": "string — the flag or mechanism that triggered delegation",
          "command": ["..."],
          "argv": ["..."],
          "classification": "...",
          "matched_rule": "...",
          "inner_commands": ["... — recursive, can nest further"]
        }
      ]
    }
  ],
  "redirects": [
    {
      "operator": "string — >, >>, <, etc.",
      "target": "string — filename or fd",
      "affects_classification": "bool"
    }
  ],
  "parse_warnings": ["string — non-fatal issues encountered during parsing"]
}
```

### Recursive classification rules

1. A command's `classification` is the **maximum** of:
   - Its own base classification (from database subcommand match)
   - Any option overrides present
   - The classification of all `inner_commands` (recursive)
   - The `min_classification` floor from `delegates_to` (if set)
   - Redirect effects

2. The top-level `classification` is the **maximum** across all top-level `commands`.

3. `inner_commands` is always an array (a delegation can produce multiple inner commands, e.g. `sh -c "ls; rm foo"` produces two inner commands from parsing the expression).

## Non-goals

- **Not a sandbox.** This is a classifier, not an enforcer. It does not execute or block anything.
- **No awk/sed/perl script analysis.** These are classified as a whole command; their embedded programs are opaque. They should simply not be in the READONLY allowlist.
- **No variable resolution.** `$DIR`, `$(cmd)` in command position → UNKNOWN. We classify what we can see statically.
- **No alias/function resolution.** We classify the literal command name as written.

## Future extensions

- `--format=decision` — output only the classification string (for use in hooks)
- `--database=/path` — custom database directory
- `--explain` — verbose output showing the matching steps
- Interactive database builder — run `command --help` and generate a skeleton YAML definition

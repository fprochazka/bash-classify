#!/usr/bin/env bash
set -euo pipefail

# Find bash-classify binary — check PATH first, then common uv/pipx locations
BASH_CLASSIFY=""
if command -v bash-classify &>/dev/null; then
  BASH_CLASSIFY="bash-classify"
elif [[ -x "$HOME/.local/bin/bash-classify" ]]; then
  BASH_CLASSIFY="$HOME/.local/bin/bash-classify"
else
  # bash-classify not installed — let normal permission flow handle it
  exit 0
fi

# Read hook input from stdin
input=$(cat)

# Extract the bash command from tool_input.command
command=$(echo "$input" | jq -r '.tool_input.command // empty')

if [[ -z "$command" ]]; then
  # No command to classify — let the normal permission flow handle it
  exit 0
fi

# Run bash-classify on the command
classification_output=$(echo "$command" | "$BASH_CLASSIFY" 2>/dev/null) || true

if [[ -z "$classification_output" ]]; then
  # Classification failed — don't interfere, let normal permission flow handle it
  exit 0
fi

# Extract the top-level classification
classification=$(echo "$classification_output" | jq -r '.classification // empty')

if [[ "$classification" == "READONLY" ]]; then
  # Auto-allow readonly commands
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
fi

# For anything else (LOCAL_EFFECTS, EXTERNAL_EFFECTS, DANGEROUS, UNKNOWN), output nothing
# — this lets the normal permission flow handle it
exit 0

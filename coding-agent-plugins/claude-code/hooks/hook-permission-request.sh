#!/usr/bin/env bash
set -euo pipefail

# Fallback hook: PreToolUse isn't consistently fired from subagents, so we
# also classify on PermissionRequest (just before the user sees the dialog)
# and auto-allow low-risk commands there.

BASH_CLASSIFY=""
if command -v bash-classify &>/dev/null; then
  BASH_CLASSIFY="bash-classify"
elif [[ -x "$HOME/.local/bin/bash-classify" ]]; then
  BASH_CLASSIFY="$HOME/.local/bin/bash-classify"
else
  exit 0
fi

input=$(cat)

command=$(echo "$input" | jq -r '.tool_input.command // empty')

if [[ -z "$command" ]]; then
  exit 0
fi

classification_output=$(echo "$command" | "$BASH_CLASSIFY" 2>/dev/null) || true

if [[ -z "$classification_output" ]]; then
  exit 0
fi

risk=$(echo "$classification_output" | jq -r '.risk // empty')

if [[ "$risk" == "LOW" ]]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}'
fi

exit 0

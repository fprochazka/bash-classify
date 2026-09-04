git add coding-agent-plugins/ && git commit -m "$(cat <<'EOF'
Add Claude Code plugin with PreToolUse hook and skill

Hook blocks `glab api .../discussions|notes`, `glab mr view --comments` and
`glab mr note` - redirects agents to the glab-discussion CLI. Leaves the
read-only commands untouched.
EOF
)"

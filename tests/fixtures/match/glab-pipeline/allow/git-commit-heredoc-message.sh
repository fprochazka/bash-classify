git add .claude-plugin/ coding-agent-plugins/ && git commit -m "$(cat <<'EOF'
Add Claude Code plugin with PreToolUse hook and skill

Hook blocks `glab ci view/get/trace`, raw `glab api .../pipelines/...`,
`/jobs/.../trace`, and `/ci/lint` calls - redirects agents to
`glab-pipeline inspect`. Leaves action commands (status/list/run/
retry/cancel/lint <file>/artifact) untouched.
EOF
)"

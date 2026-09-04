cd /tmp/work/project/.worktrees/feature
glab mr update 123 --draft 2>&1 | tail -3
glab mr view 123 --output json 2>&1 | jq '{draft, title, state}'

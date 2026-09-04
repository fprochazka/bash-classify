cd /tmp/work/project/.worktrees/feature
glab ci status --compact 2>&1 | head -3; echo "..."; glab mr view 123 2>&1 | grep -i pipeline

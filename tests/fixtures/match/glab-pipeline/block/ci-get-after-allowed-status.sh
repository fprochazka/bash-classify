cd /tmp/work/project/.worktrees/feature
glab ci status --compact 2>&1 | head -30 || glab ci get -F json 2>&1 | head -5

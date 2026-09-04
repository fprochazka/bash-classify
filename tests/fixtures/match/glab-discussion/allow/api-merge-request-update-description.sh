cd /tmp/work/other-project/.worktrees/feature && glab api -X PUT "projects/:id/merge_requests/123" -f description="$(cat /tmp/work/mr-description-v4.md)" 2>/dev/null | jq -r '.sha'

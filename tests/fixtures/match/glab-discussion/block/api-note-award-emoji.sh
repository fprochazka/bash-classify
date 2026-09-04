cd /tmp/work/other-project/.worktrees/feature && glab api -X POST "projects/:id/merge_requests/123/notes/3000/award_emoji" -f name=recycle 2>&1 | tail -2

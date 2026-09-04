cd /tmp/work/project/.worktrees/feature && glab api "projects/42/merge_requests/123/discussions" -X GET -f per_page=100 --paginate 2>/dev/null | jq -s 'add // []' | jq 'length'

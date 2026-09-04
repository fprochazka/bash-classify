glab api -R group/project "projects/:id/merge_requests/123/discussions" --paginate 2>&1 | jq '[.[] | select(.resolved == false)] | length'

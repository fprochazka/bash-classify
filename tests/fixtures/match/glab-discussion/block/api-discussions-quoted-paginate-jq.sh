glab api "projects/:id/merge_requests/123/discussions" --paginate 2>/dev/null | jq -r '.[] | "\(.id) \(.notes[0].author.username)"'

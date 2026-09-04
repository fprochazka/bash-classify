glab api projects/:id/merge_requests/123/discussions --paginate --output ndjson 2>/dev/null \
| jq -r '.notes[] | select(.system==false) | "----- \(.author.username)"'

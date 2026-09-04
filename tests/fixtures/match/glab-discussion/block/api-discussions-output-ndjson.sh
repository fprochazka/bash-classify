glab api projects/:id/merge_requests/123/discussions --paginate --output ndjson 2>&1 | jq -r 'select(.notes[0].body | test("push back")) | .id'

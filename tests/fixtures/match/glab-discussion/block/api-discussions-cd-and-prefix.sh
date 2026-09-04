cd /tmp/work/project && glab api projects/:id/merge_requests/123/discussions --paginate 2>&1 | jq '.' > /tmp/work/mr-123-discussions.json && echo "done"

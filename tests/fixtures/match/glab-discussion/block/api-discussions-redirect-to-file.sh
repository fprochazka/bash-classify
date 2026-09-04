glab api projects/42/merge_requests/123/discussions --paginate > /tmp/work/mr-123-discussions.json 2>&1; echo "fetched"; jq 'length' /tmp/work/mr-123-discussions.json

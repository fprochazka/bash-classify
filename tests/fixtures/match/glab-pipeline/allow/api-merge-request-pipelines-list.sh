glab api "projects/group%2Fproject/merge_requests/123/pipelines" | jq -c '.[0] | {id, status}'

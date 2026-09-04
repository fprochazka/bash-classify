glab api "projects/:id/pipelines/1000/jobs?per_page=100" | jq '.[] | {name, status, stage}' | head -200

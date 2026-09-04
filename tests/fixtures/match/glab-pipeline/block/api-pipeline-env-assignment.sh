GITLAB_HOST=gitlab.example.com glab api "projects/42/pipelines/1000" 2>/dev/null | jq -r '.status'

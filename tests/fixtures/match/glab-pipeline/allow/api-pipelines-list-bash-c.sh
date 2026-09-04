bash -c 's=$(glab api "projects/:id/pipelines?ref=feature/branch&per_page=1" | jq -r ".[0].status"); echo "status=$s"'

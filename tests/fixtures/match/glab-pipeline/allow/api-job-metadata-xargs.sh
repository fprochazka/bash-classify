jq -r '.[] | select(.name=="build-app") | .id' /tmp/work/jobs.json 2>/dev/null | head -1 | xargs -I{} glab api "projects/:id/jobs/{}" 2>/dev/null | jq '{name, artifacts_file}'

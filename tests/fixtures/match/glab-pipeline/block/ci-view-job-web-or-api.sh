glab ci view lint --web 2>/dev/null || glab api "projects/group%2Fproject/pipelines/1000/jobs" 2>&1 | jq -r '.[] | select(.name == "lint") | .id'

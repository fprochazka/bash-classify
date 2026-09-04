glab api projects/group%2Fproject/jobs/2000 2>/dev/null | jq '{name, status}'; echo ---; glab api "projects/group%2Fproject/jobs/2000/trace" 2>/dev/null | tail -40

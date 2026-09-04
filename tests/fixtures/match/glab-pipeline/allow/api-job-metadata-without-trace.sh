glab api projects/:id/jobs/2000 2>/dev/null | jq -r '"\(.name): \(.status)"'

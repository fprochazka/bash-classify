cd /tmp/work && echo "=== !123 notes ==="; timeout 120 glab api "projects/42/merge_requests/123/notes?per_page=20" 2>&1 | jq -r '.[]? | "\(.author.username)"' | head -20

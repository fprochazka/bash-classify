# Check the earlier failed pipelines on this branch to see which jobs failed
for pid in 1000 1001 1002 1003; do
  echo "=== Pipeline $pid ==="
  glab api "projects/:id/pipelines/$pid/jobs?per_page=100" 2>&1 | jq '[.[] | select(.status == "failed") | {id, name}]'
done

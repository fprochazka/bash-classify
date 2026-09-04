cd /tmp/work/scratchpad && for p in 1000 1001; do
  jobs=$(timeout 60 glab api "projects/:fullpath/pipelines/$p/jobs?per_page=100" 2>/dev/null | jq -r '.[] | .id')
  for j in $jobs; do
    echo "$p $j"
  done
done

for iid in 123 124; do
  echo -n "MR !$iid: "
  glab api "projects/group%2Fproject/merge_requests/$iid/pipelines?per_page=5" \
    --hostname gitlab.example.com 2>/dev/null | jq -r '.[] | [.id, .status] | @tsv' | head -1
done

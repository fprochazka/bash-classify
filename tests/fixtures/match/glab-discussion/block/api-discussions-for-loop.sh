for iid in 123 124 125; do echo "=== !$iid"; glab api "projects/group%2Fproject/merge_requests/$iid/discussions" --paginate 2>/dev/null | jq -r 'length'; done

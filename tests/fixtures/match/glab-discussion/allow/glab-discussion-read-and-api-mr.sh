for m in 123 124; do glab api projects/:id/merge_requests/$m 2>/dev/null | jq -r '.state'; done; echo "--- threads:"; glab-discussion read --mr-iid 123 2>&1 | tail -3

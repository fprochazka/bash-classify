glab api -X PUT projects/:id/merge_requests/123/notes/3000 -f body="$(cat <<'EOF'
Updated summary after the rebase.

- item one
- item two
EOF
)"

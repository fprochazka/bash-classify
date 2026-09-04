glab api "projects/42/merge_requests/123/discussions/0123456789abcdef0123456789abcdef01234567/notes" --method POST --raw-field "$(cat <<'EOF'
body=All points addressed or dismissed:

**First point** - the helper already returns the right type.
EOF
)"

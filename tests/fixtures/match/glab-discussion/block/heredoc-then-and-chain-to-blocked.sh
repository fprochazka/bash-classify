cat > /tmp/work/reply.md <<'EOF' && glab api -X POST "projects/42/merge_requests/123/discussions/0123456789abcdef0123456789abcdef01234567/notes" -f body="$(cat /tmp/work/reply.md)"
Addressed in `abc1234`.
EOF

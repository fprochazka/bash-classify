glab api -X POST "projects/:id/merge_requests/123/discussions/0123456789abcdef0123456789abcdef01234567/notes" \
  -f body="$(cat <<'EOF'
Addressed in `abc1234`:

**First finding** - Fixed. The conversion now uses the checked helper.
**Third finding** - No change; explained in the thread above.
EOF
)"

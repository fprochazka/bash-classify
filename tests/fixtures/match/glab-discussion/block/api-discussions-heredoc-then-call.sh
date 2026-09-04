mkdir -p /tmp/work/review-report && cat > /tmp/work/review-report/ticket-123.babysit.md <<'EOF'
# Babysit ledger: TICKET-123 (MR !123)

- MRs: group/project!123 - /tmp/work/project/.worktrees/feature - draft yes
- Ticket: TICKET-123
- Mode: working
EOF
echo "ledger written"; glab api "projects/:id/merge_requests/123/discussions" --paginate 2>/dev/null | jq -r 'length' | xargs -I{} echo "non-system discussions: {}"

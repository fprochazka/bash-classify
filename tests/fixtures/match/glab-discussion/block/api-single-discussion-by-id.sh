glab api "projects/:id/merge_requests/123/discussions/0123456789abcdef0123456789abcdef01234567" 2>/dev/null | jq -r '{individual_note, notes: [.notes[] | {id, resolved}]}'

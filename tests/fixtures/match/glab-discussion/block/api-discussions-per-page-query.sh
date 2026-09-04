glab api "projects/group%2Fproject/merge_requests/123/discussions?per_page=100" 2>/dev/null | jq -r '.[] | select(.notes[0].system == false) | .id' | head -300

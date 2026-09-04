# So DiscussionNote appears in both APIs. Check how it differs from DiffNote
# in the discussions endpoint - do DiscussionNotes carry a position?
glab api "projects/42/merge_requests/123/discussions?per_page=100" --hostname gitlab.example.com 2>&1 | python3 -c "
import json, sys
data = json.load(sys.stdin)
for disc in data:
    for note in disc.get('notes', []):
        print(note.get('type'), note.get('position') is not None)
"

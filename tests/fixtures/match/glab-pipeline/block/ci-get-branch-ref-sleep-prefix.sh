sleep 180; glab ci get -b refs/merge-requests/123/head -F json 2>/dev/null | jq -r '.jobs[]? | .name' | tail -3

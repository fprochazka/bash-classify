glab mr note list 123 -R group/project --output json 2>&1 | jq '[.[] | select(.resolved == false)] | length' 2>&1

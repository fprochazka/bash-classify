cd /tmp/work/project/.worktrees/feature
export GITLAB_HOST=gitlab.example.com
for iid in 123 124 125; do
echo "=== !$iid ==="
glab api "projects/group%2Fproject/merge_requests/$iid/discussions?per_page=100" 2>/dev/null | jq -r '
  [ .[] | {a: .notes[0].author.username, n: (.notes|length)} ]
  | group_by(.a) | .[] | "\(.[0].a)\tthreads=\(length)"'
done

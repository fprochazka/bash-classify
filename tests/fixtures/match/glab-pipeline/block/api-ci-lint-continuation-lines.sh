glab api -X POST "projects/group%2Fproject/ci/lint" \
  --hostname gitlab.example.com \
  -F include_merged_yaml=true \
  -f content="$(cat /tmp/work/scratchpad/flat-ci.yml)" > /tmp/work/scratchpad/lint-result.json 2>&1
echo "exit=$?"

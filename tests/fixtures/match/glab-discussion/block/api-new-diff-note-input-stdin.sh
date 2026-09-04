echo '{"body":"CLI test - please ignore"}' | glab api -X POST projects/group%2Fproject/merge_requests/123/discussions --hostname gitlab.example.com --input - 2>&1

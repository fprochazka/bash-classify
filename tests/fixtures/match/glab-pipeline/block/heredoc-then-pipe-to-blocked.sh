cat <<'EOF' | glab api -X POST projects/group%2Fproject/ci/lint --input -
{"content": "stages:\n  - build\n", "include_merged_yaml": true}
EOF

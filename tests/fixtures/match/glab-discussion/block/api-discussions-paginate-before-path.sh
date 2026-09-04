cd /tmp/work && HOST="gitlab.example.com"; REPO="group/project"; IID=123; ENC="${REPO//\//%2F}"
echo "=== fallback with --hostname"
glab api --hostname "$HOST" --paginate "projects/$ENC/merge_requests/$IID/discussions?per_page=100" 2>&1 | head -20

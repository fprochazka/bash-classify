git fetch origin master --quiet 2>&1 | tail -1
echo "=== behind master by ==="; git rev-list --count HEAD..origin/master
echo "=== pipeline status ==="; glab ci get -R group/project --branch feature/TICKET-123 2>/dev/null | grep -iE 'status' | head -8

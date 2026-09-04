glab api "projects/42/pipelines/1000/jobs?per_page=100" 2>&1 | python3 -c "
import json, sys
data = json.load(sys.stdin)
for j in data:
    print(j['id'], j['stage'], j['name'], j['status'])
"

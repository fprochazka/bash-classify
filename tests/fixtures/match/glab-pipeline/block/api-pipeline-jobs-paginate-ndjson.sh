glab api "projects/group%2Fproject/pipelines/1000/jobs?per_page=100" --paginate --output ndjson \
  | jq -r '. | "\(.status)\t\(.stage)\t\(.name)"' | sort

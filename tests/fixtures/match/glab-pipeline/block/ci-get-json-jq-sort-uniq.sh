glab ci get --with-job-details -F json 2>/dev/null | jq -r '.jobs[] | "\(.status)\t\(.name)"' | sort | uniq -c | sort -rn

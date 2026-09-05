glab pipe get -p 1000 --with-job-details -F json 2>/dev/null | jq -r '.jobs[] | "\(.status)\t\(.name)"'

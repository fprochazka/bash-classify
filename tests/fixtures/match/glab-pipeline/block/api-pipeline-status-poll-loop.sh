for i in $(seq 1 28); do
  st=$(glab api projects/:id/pipelines/1000 2>/dev/null | jq -r '.status // "unknown"')
  echo "[poll $i] pipeline 1000: $st"
  case "$st" in success|failed|canceled|skipped) echo "TERMINAL: $st"; break;; esac
  sleep 30
done

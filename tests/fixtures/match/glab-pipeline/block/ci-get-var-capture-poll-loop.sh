for i in $(seq 1 60); do
  json=$(glab ci get -F json 2>/dev/null)
  st=$(echo "$json" | jq -r '.status // empty' 2>/dev/null)
  case "$st" in
    success) echo "PIPELINE SUCCESS"; exit 0 ;;
  esac
  sleep 30
done
echo "TIMEOUT"

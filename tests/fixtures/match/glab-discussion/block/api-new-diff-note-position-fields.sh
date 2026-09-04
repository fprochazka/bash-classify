glab api -X POST projects/group%2Fproject/merge_requests/123/discussions \
  --hostname gitlab.example.com \
  -f 'body=CLI test - please ignore' \
  -f 'position[position_type]=text' \
  -f 'position[new_path]=src/main/java/com/acme/Mapper.java' \
  -f 'position[new_line]=42'

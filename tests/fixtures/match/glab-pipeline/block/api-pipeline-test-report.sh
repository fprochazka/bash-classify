# Get the test report GitLab builds from the JUnit artifacts
glab api --hostname gitlab.example.com \
  "projects/group%2Fproject/pipelines/1000/test_report" | jq '.test_suites[] | .name'

GITLAB_HOST=gitlab.example.com glab api "projects/42/jobs/2000/trace" 2>/dev/null | grep -i "test-env" | head -20

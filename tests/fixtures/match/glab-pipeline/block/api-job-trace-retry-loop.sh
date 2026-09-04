for i in 1 2 3; do glab api "projects/group%2Fproject/jobs/2000/trace" > /tmp/work/job-2000.log 2>/tmp/work/err-trace && break || sleep $((i*5)); done; wc -l /tmp/work/job-2000.log

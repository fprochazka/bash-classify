cd /tmp/work/project/.worktrees/feature
jobid=$(glab ci get --pipeline 1000 2>/dev/null | grep -oE "[0-9]{7,}" | head -1)
echo "job id: $jobid"
glab ci trace "$jobid" 2>/dev/null > /tmp/work/tests-trace.log; wc -l /tmp/work/tests-trace.log

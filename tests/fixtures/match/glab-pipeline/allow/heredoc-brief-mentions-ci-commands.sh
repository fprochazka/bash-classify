mkdir -p /tmp/work/mr-maintenance && cat > /tmp/work/mr-maintenance/pipeline-brief.md <<'EOF'
# Brief - pipeline triage

For every MR with a red pipeline, report the failing job and the first real error line.

**Blocked by a wrapper - do not attempt:** `glab ci view`, `glab ci get`, `glab ci trace`,
raw `glab api projects/<enc>/pipelines/<id>/jobs`, `glab api .../jobs/<id>/trace`, and
`glab api .../ci/lint`. Use `glab-pipeline inspect` instead: it dumps pipeline.json,
jobs.json and the per-job logs in one pass.

Allowed for context: `glab ci list`, `glab ci status --compact`, and the pipelines LIST
endpoint `glab api "projects/<enc>/pipelines?ref=<branch>"`.

Read-only. Do not retry, cancel or trigger anything.
EOF
echo written

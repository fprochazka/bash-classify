cat > /tmp/work/mr-maintenance/collect-brief.md <<'EOF'
# MR review-state collection brief

Collect per-MR review state for the merge requests listed below, on host `gitlab.example.com`.

- **Last HUMAN activity date**: the later of (a) the newest non-bot note in the discussion
  dump, and (b) the head commit's `committed_date`.

`glab api` against a merge request's `notes` or `discussions` sub-resource is BLOCKED by a
wrapper, as are `glab mr view --comments` and `glab mr note`. Do not attempt them.

Read-only. Do not post, resolve, rebase, approve or modify anything.
EOF
echo written

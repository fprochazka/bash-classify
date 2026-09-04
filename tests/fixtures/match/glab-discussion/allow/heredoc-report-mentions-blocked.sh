cat > /tmp/work/mr-maintenance/mr-review-state.md <<'REPORT'
# MR review state - 2026-08-26

| MR | author | AI verdict | unresolved bot | unresolved human |
|---|---|---|---|---|
| group/project!123 | alice | green | 0 | 2 |

- **Blocked commands were not attempted**: no `glab api` against `notes`/`discussions`, no
  `glab mr view --comments`, no `glab mr note`. Threads came from `glab-discussion read --dump`.
REPORT

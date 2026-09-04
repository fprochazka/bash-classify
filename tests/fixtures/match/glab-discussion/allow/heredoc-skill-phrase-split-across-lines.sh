cat > /tmp/work/skills/acme-mr-maintain/SKILL.md <<'SKILLEOF'
---
name: acme-mr-maintain
description: Daily triage of every open merge request across the team's GitLab repos.
---

- **Blocked commands.** `glab api .../notes`, `.../discussions`, `glab mr view --comments` and
`glab mr note` are blocked by a wrapper. Read threads only via `glab-discussion read --mr-url`.
SKILLEOF
wc -w /tmp/work/skills/acme-mr-maintain/SKILL.md

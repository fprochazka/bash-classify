mkdir -p /tmp/work/plugins/sdlc/skills/mr-status && cat > /tmp/work/plugins/sdlc/skills/mr-status/SKILL.md <<'SKILLEOF'
---
name: mr-status
description: Determine the review-and-merge status of one merge request or a set of them.
---

Prefer `glab-discussion read --dump` for all comment data. It writes one file per thread
and it handles pagination. Raw `glab api projects/<enc>/merge_requests/<iid>/discussions`
is the fallback when that CLI is absent.
SKILLEOF
wc -l /tmp/work/plugins/sdlc/skills/mr-status/SKILL.md

cat > /tmp/work/plugins/glab-pipeline/skills/SKILL.md <<'SKILLEOF'
---
name: glab-pipeline
description: Inspect a GitLab CI pipeline.
---

Never call `glab ci get` or `glab api projects/<enc>/pipelines/<id>/jobs` directly.
`glab-pipeline inspect` writes the same data to files and prints a problem-driven summary.
SKILLEOF
wc -l /tmp/work/plugins/glab-pipeline/skills/SKILL.md

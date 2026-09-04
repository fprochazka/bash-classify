cd /tmp/work/infra-project && glab mr note 123 -m "$(cat <<'MEOF'
## Why this looks different from MR !100

**No config changes in this MR:**

!100 kept the flow authenticated. This MR makes it open.
MEOF
)"

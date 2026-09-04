python3 - <<'PY'
p = "plugins/glab/README.md"
s = open(p).read()

old = '''## How it works

1. Auto-detects the MR from the current git branch
2. Fetches MR info via `glab mr view`
3. Delegates discussion fetching to `glab-discussion read --dump`
'''
assert old in s
open(p, "w").write(s)
print("ok")
PY
grep -n "glab-pipeline\|job-logs" plugins/glab/README.md

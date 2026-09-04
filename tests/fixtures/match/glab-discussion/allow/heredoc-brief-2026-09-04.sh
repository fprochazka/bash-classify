mkdir -p /tmp/work/mr-maintenance/20260904-0713 && cat > /tmp/work/mr-maintenance/20260904-0713/brief-collect.md <<'EOF'
# Brief - MR state re-collection, run 20260904-0713

**First, invoke the `glab:mr-status` skill to load its usage guidance before running any
commands.** Also load `glab` and `glab-discussion`.

GitLab host is `gitlab.example.com`. Working dir for all outputs:
`/tmp/work/mr-maintenance/20260904-0713/`

This is a **re-collection**. A previous sweep ran on 2026-08-31 and its outputs are in
`../20260831-1112/`. Four days have passed. Everything in it is stale. **Do not trust any
state from it** - it is there only so you can report what changed.

## Step 1 - rediscover the open MR set

Owned repos (sweep **all** open MRs):
- `group/project` (`group%2Fproject`)
- `group/other-project` (`group%2Fother-project`)

Foreign repos (sweep open MRs, then keep **only** those authored by a human team member -
`alice`, `bob`, `carol`, `dave`):
- `acme/shared-lib`, `acme/framework`, `group/config-repo`

**SCOPE TRAP - this cost the last run 232 wrong MRs.** `code-bot` authors MRs across the
whole organization. It is a team author **only in the two owned repos**.

Use `--paginate`. Write the full open-MR list to `open-mrs.tsv`.

Classify each MR as renovate or not: renovate MRs are authored by `renovate` **or** titled
`chore(deps):`. Renovate MRs are **counted and reported only**.

Write `mr-set.tsv` with columns `repo`, `iid`, `author`, `draft`, `collect_threads`.

## Step 2 - per-MR state

For every MR in `mr-set.tsv`, from
`glab api "projects/<enc>/merge_requests/<iid>?include_diverged_commits_count=true"`:

- `draft`, `state`, `title`, `web_url`, `sha`, `created_at`, `updated_at`
- `has_conflicts`, `merge_status`, `detailed_merge_status`, `diverged_commits_count`
- `head_pipeline.status`, `head_pipeline.sha`, `head_pipeline.id`
- approvals: `glab api "projects/<enc>/merge_requests/<iid>/approvals"` - who approved

**`has_conflicts` is uncomputed while `merge_status` is `checking`** - there `false` is a
default, not an answer. Report it as *unknown*, never as *no conflict*.

## Step 3 - threads, where `collect_threads` is `yes`

```bash
glab-discussion read --mr-url "https://gitlab.example.com/<repo>/-/merge_requests/<iid>" --dump
```

Always `--mr-url`; the `--project` / `--mr-iid` flags are unreliable.

**The grep token for an unresolved thread is `Resolved: no`, NOT `Resolved: false`.**

## AI reviewer semantics

- **`ai-reviewer`** - CI-triggered. One summary thread it edits in place. Verdicts
  `Merge`, `Review`, `Fix`. **Record the verdict sha** - a verdict for a superseded sha is
  stale. It does not read replies.
- **`code-bot`** - manual, mention-triggered. Re-posts a summary per round in the same
  thread - **read the last note only**. It does read replies.
- **`auto-approver`** approval is **not** human review. Report it separately.

## Hard rules

- **Read-only.** No rebase, no comment, no thread resolution, no approval.
- **Blocked by a wrapper - do not attempt:** `glab api` against an MR's `notes` or
  `discussions` sub-resource, `glab mr view --comments`, `glab mr note`, the pipeline-jobs API.
- For a red pipeline, name the failing job through the `glab-pipeline` skill.
- **Never measure an exit code through a pipe** - `cmd | head` reports `head`'s status.
  Redirect to a file, then inspect.
- `glab api` output can carry control characters that break `jq`. Redirect to a file first.
- **`/commits` and every list endpoint paginate at 20.** Always `--paginate` where a count
  matters.

## Output

Write `mr-review-state.md` in the run dir: a summary table with one row per MR, then one
section per MR headed `## <repo>!<iid> - <MR title>`.

Also write `changes-vs-0831.md`: MRs that are **new** since `../20260831-1112/mr-set.tsv`,
MRs from that set that are now **merged or closed**, and MRs whose draft flag changed.

Report back: counts collected, any MR that failed to collect and why.
EOF
echo written; wc -l /tmp/work/mr-maintenance/20260904-0713/brief-collect.md

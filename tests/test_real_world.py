"""Tests based on real-world bash patterns from Claude Code transcripts."""

from bash_classify.classifier import classify_expression
from bash_classify.models import Classification


class TestGitWorkflows:
    """Git commands — the most common patterns from real usage."""

    def test_git_status(self, database):
        result = classify_expression("git status", database)
        assert result.classification == Classification.READONLY

    def test_git_status_short(self, database):
        # strict: false on git status allows unknown flags to pass through
        result = classify_expression("git status --short", database)
        assert result.classification == Classification.READONLY

    def test_git_diff_stat(self, database):
        result = classify_expression("git diff --stat", database)
        assert result.classification == Classification.READONLY

    def test_git_diff_cached(self, database):
        result = classify_expression("git diff --cached", database)
        assert result.classification == Classification.READONLY

    def test_git_diff_cached_stat(self, database):
        result = classify_expression("git diff --cached --stat", database)
        assert result.classification == Classification.READONLY

    def test_git_log_oneline(self, database):
        result = classify_expression("git log --oneline -5", database)
        assert result.classification == Classification.READONLY

    def test_git_log_range(self, database):
        result = classify_expression("git log master..HEAD --oneline", database)
        assert result.classification == Classification.READONLY

    def test_git_diff_range(self, database):
        result = classify_expression("git diff master...HEAD", database)
        assert result.classification == Classification.READONLY

    def test_git_show_historical(self, database):
        result = classify_expression("git show HEAD~10:src/main.py", database)
        assert result.classification == Classification.READONLY

    def test_git_add_and_commit(self, database):
        result = classify_expression('git add -A && git commit -m "fix: resolve issue"', database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_add_diff_cached(self, database):
        result = classify_expression("git add -A && git diff --cached --stat", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_amend_no_edit(self, database):
        result = classify_expression("git add -A && git commit --amend --no-edit", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_amend_and_force_push(self, database):
        result = classify_expression(
            "git add -A && git commit --amend --no-edit && git push --force-with-lease", database
        )
        assert result.classification == Classification.EXTERNAL_EFFECTS

    def test_git_push_force(self, database):
        result = classify_expression("git push --force origin main", database)
        assert result.classification == Classification.DANGEROUS

    def test_git_rebase_continue(self, database):
        result = classify_expression("git rebase --continue", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_reset_soft(self, database):
        result = classify_expression("git reset --soft HEAD~1", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_c_flag(self, database):
        result = classify_expression("git -C /home/user/repos/myrepo status", database)
        assert result.classification == Classification.READONLY

    def test_env_prefix_git_rebase(self, database):
        # GIT_EDITOR=true is a variable assignment stripped by parser;
        # git rebase --continue is now recognized
        result = classify_expression("GIT_EDITOR=true git rebase --continue", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_git_rm_during_rebase(self, database):
        # git rm is LOCAL_EFFECTS, git rebase --continue is LOCAL_EFFECTS -> overall LOCAL_EFFECTS
        result = classify_expression("git rm conflicted-file.txt && git rebase --continue", database)
        assert result.classification == Classification.LOCAL_EFFECTS


class TestBuildAndTest:
    """Build tool commands — Maven, pytest, npm, etc."""

    def test_mvnw_package_with_grep(self, database):
        """Maven build piped to grep for error filtering."""
        result = classify_expression(
            './mvnw package -DskipTests --batch-mode 2>&1 | grep -E "\\[ERROR\\]|BUILD"', database
        )
        # ./mvnw is LOCAL_EFFECTS (builds locally), grep is READONLY -> LOCAL_EFFECTS overall
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_mvnw_with_tail(self, database):
        """Maven build piped to tail — most common pattern."""
        result = classify_expression("./mvnw package --batch-mode -DskipTests=true 2>&1 | tail -30", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_pytest_verbose(self, database):
        # uv run pytest is a known safe subcommand -> LOCAL_EFFECTS
        result = classify_expression("uv run pytest -v --tb=short", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_npm_test(self, database):
        result = classify_expression("npm test", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_npm_run_build(self, database):
        result = classify_expression("npm run build", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_npm_install(self, database):
        result = classify_expression("npm install", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_ruff_check_and_format(self, database):
        result = classify_expression("ruff check --fix . && ruff format .", database)
        # ruff check --fix is LOCAL_EFFECTS, ruff format is LOCAL_EFFECTS -> LOCAL_EFFECTS
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_make_with_target(self, database):
        result = classify_expression("make build", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_make_dry_run(self, database):
        result = classify_expression("make -n install", database)
        assert result.classification == Classification.READONLY


class TestPipesAndGrep:
    """Pipeline patterns — very common in real usage."""

    def test_grep_with_head(self, database):
        result = classify_expression('grep -E "pattern1|pattern2" file.txt | head -20', database)
        assert result.classification == Classification.READONLY

    def test_grep_case_insensitive_with_tail(self, database):
        result = classify_expression("grep -i 'search_term' logfile | tail -5", database)
        assert result.classification == Classification.READONLY

    def test_grep_with_line_numbers_sort_uniq(self, database):
        result = classify_expression('grep -n "pattern" file | sort | uniq', database)
        assert result.classification == Classification.READONLY

    def test_grep_context_lines(self, database):
        result = classify_expression('grep -A 20 "search_term" file.txt | head -30', database)
        assert result.classification == Classification.READONLY

    def test_grep_before_and_after(self, database):
        result = classify_expression('grep -B 5 -A 10 "pattern" file.txt', database)
        assert result.classification == Classification.READONLY

    def test_grep_inverse_pipe(self, database):
        """Double grep: first match, then exclude — common for build output filtering."""
        result = classify_expression('grep -iE "\\[WARN\\]|\\[ERROR\\]" output.log | grep -v "^\\[INFO\\]"', database)
        assert result.classification == Classification.READONLY

    def test_cat_pipe_head(self, database):
        result = classify_expression("cat /path/to/file | head -100", database)
        assert result.classification == Classification.READONLY

    def test_find_pipe_head(self, database):
        result = classify_expression('find /home/user/project -type f -name "*.java" | head -20', database)
        assert result.classification == Classification.READONLY

    def test_ls_pipe_tail(self, database):
        result = classify_expression("ls /path/to/dir | tail -5", database)
        assert result.classification == Classification.READONLY

    def test_sort_pipe_uniq_count_sort(self, database):
        """Common pattern: frequency analysis."""
        result = classify_expression('awk "{print $1}" access.log | sort | uniq -c | sort -rn | head -20', database)
        assert result.classification == Classification.READONLY

    def test_ps_pipe_grep(self, database):
        result = classify_expression("ps aux | grep python", database)
        assert result.classification == Classification.READONLY

    def test_wc_l_pipeline(self, database):
        result = classify_expression('find . -name "*.py" | wc -l', database)
        assert result.classification == Classification.READONLY


class TestCommandChains:
    """Chained commands with &&, ||, ; operators."""

    def test_and_chain_readonly(self, database):
        result = classify_expression("git status && git log --oneline -3", database)
        assert result.classification == Classification.READONLY

    def test_and_chain_mixed(self, database):
        result = classify_expression("git add -A && git diff --cached --stat", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_or_chain_with_echo_fallback(self, database):
        result = classify_expression('cat /path/to/file || echo "file not found"', database)
        assert result.classification == Classification.READONLY

    def test_semicolon_chain(self, database):
        result = classify_expression("echo start; ls -la; echo done", database)
        assert result.classification == Classification.READONLY

    def test_docker_cleanup_chain(self, database):
        """Docker cleanup with xargs and semicolon."""
        result = classify_expression(
            'docker ps -aq --filter "label=test" | xargs -r docker rm -f 2>/dev/null; echo "done"',
            database,
        )
        assert result.classification == Classification.DANGEROUS

    def test_cd_and_command(self, database):
        result = classify_expression("cd /home/user/project && ls -la", database)
        assert result.classification == Classification.READONLY

    def test_mkdir_or_fallback(self, database):
        result = classify_expression("cd /nonexistent || mkdir -p /home/user/tmp/workdir", database)
        assert result.classification == Classification.LOCAL_EFFECTS


class TestRedirects:
    """Redirect patterns from real usage."""

    def test_stderr_to_stdout_pipe(self, database):
        """2>&1 piped to grep — extremely common build pattern."""
        result = classify_expression('./build.sh 2>&1 | grep -E "ERROR|FAILURE"', database)
        # ./build.sh is UNKNOWN
        assert result.classification == Classification.UNKNOWN

    def test_stderr_to_dev_null(self, database):
        result = classify_expression('find /path -name "*.log" 2>/dev/null', database)
        assert result.classification == Classification.READONLY

    def test_redirect_to_file(self, database):
        result = classify_expression("echo hello > /tmp/test.txt", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_append_redirect(self, database):
        result = classify_expression("echo line >> /tmp/log.txt", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_unzip_with_fallback(self, database):
        """Extract or echo 'not found' — common inspection pattern."""
        result = classify_expression(
            'unzip -p archive.jar META-INF/MANIFEST.MF 2>/dev/null || echo "not found"', database
        )
        # unzip -p is not a recognized option (only -l overrides to READONLY),
        # so base LOCAL_EFFECTS classification applies
        assert result.classification == Classification.LOCAL_EFFECTS


class TestHeredocs:
    """Heredoc patterns — common in git commits."""

    def test_git_commit_with_heredoc(self, database):
        result = classify_expression(
            """git commit -m "$(cat <<'EOF'
Fix authentication bug in login flow

The session token was not being refreshed properly.
EOF
)" """,
            database,
        )
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_cat_heredoc(self, database):
        result = classify_expression(
            """cat <<'EOF'
hello world
this is content
EOF""",
            database,
        )
        assert result.classification == Classification.READONLY


class TestVariableExpansion:
    """Variable and command substitution patterns."""

    def test_variable_in_command_position(self, database):
        result = classify_expression("$CMD arg1 arg2", database)
        assert result.classification == Classification.DANGEROUS

    def test_env_prefix_command(self, database):
        result = classify_expression("FOO=bar BAZ=1 echo hello", database)
        assert result.classification == Classification.READONLY

    def test_date_format(self, database):
        result = classify_expression("date '+%Y%m%d%H%M%S'", database)
        assert result.classification == Classification.READONLY


class TestKubernetes:
    """Kubernetes patterns."""

    def test_kubectl_get_wide(self, database):
        result = classify_expression("kubectl get pods --context my-cluster -n my-namespace -o wide", database)
        assert result.classification == Classification.READONLY

    def test_kubectl_get_deployment(self, database):
        result = classify_expression("kubectl get deployment my-app --context my-cluster -o yaml", database)
        assert result.classification == Classification.READONLY

    def test_kubectl_logs_tail(self, database):
        result = classify_expression("kubectl logs my-pod --tail=30", database)
        assert result.classification == Classification.READONLY

    def test_kubectl_exec_cat(self, database):
        result = classify_expression("kubectl exec -it my-pod -- cat /etc/config", database)
        assert result.classification == Classification.DANGEROUS

    def test_kubectl_apply(self, database):
        result = classify_expression("kubectl apply -f deployment.yaml", database)
        assert result.classification == Classification.EXTERNAL_EFFECTS

    def test_kubectl_apply_dry_run(self, database):
        result = classify_expression("kubectl apply --dry-run=client -f deployment.yaml", database)
        assert result.classification == Classification.READONLY


class TestDockerPatterns:
    """Docker patterns."""

    def test_docker_ps(self, database):
        result = classify_expression("docker ps -a", database)
        assert result.classification == Classification.READONLY

    def test_docker_run(self, database):
        result = classify_expression("docker run --rm python:3.12-slim echo hello", database)
        assert result.classification == Classification.DANGEROUS

    def test_docker_run_with_volume(self, database):
        result = classify_expression(
            'docker run --rm -v "$(pwd):/app:ro" python:3.12-slim cat /app/README.md', database
        )
        assert result.classification == Classification.DANGEROUS

    def test_docker_images(self, database):
        result = classify_expression("docker images", database)
        assert result.classification == Classification.READONLY

    def test_docker_system_prune(self, database):
        result = classify_expression("docker system prune -af", database)
        assert result.classification == Classification.DANGEROUS


class TestFileOperations:
    """File and directory operations."""

    def test_find_with_maxdepth(self, database):
        result = classify_expression('find /path -maxdepth 4 -name "*.json" 2>/dev/null', database)
        assert result.classification == Classification.READONLY

    def test_find_type_f_pipe_head(self, database):
        result = classify_expression('find . -type f -name "*.py" | head -20', database)
        assert result.classification == Classification.READONLY

    def test_find_delete(self, database):
        result = classify_expression('find . -name "*.pyc" -delete', database)
        assert result.classification == Classification.DANGEROUS

    def test_xargs_grep(self, database):
        """xargs with readonly inner command."""
        result = classify_expression('find . -name "*.py" | xargs grep "TODO"', database)
        assert result.classification == Classification.READONLY

    def test_xargs_rm(self, database):
        """xargs with dangerous inner command."""
        result = classify_expression('find /tmp -name "*.tmp" | xargs rm', database)
        assert result.classification == Classification.DANGEROUS

    def test_cp_to_tmp(self, database):
        result = classify_expression("cp file.txt /tmp/backup.txt", database)
        assert result.classification == Classification.LOCAL_EFFECTS

    def test_cp_to_etc(self, database):
        result = classify_expression("cp config.txt /etc/myapp/config", database)
        assert result.classification == Classification.DANGEROUS

    def test_mkdir_p(self, database):
        result = classify_expression("mkdir -p /home/user/project/src", database)
        assert result.classification == Classification.LOCAL_EFFECTS


class TestComplexRealWorld:
    """Complex multi-step real-world patterns."""

    def test_source_and_build(self, database):
        """Source environment then build — common Java/SDK pattern."""
        result = classify_expression('source "$HOME/.sdkman/bin/sdkman-init.sh" && make build', database)
        assert result.classification == Classification.DANGEROUS  # source is DANGEROUS

    def test_conditional_test(self, database):
        """Bash conditional — test file then cat it."""
        result = classify_expression('[ -f "file.txt" ] && cat file.txt', database)
        assert result.classification == Classification.READONLY

    def test_double_bracket_test(self, database):
        result = classify_expression('[[ -d "$dir" ]] && echo "found" || echo "not found"', database)
        assert result.classification == Classification.READONLY

    def test_for_loop_echo(self, database):
        """For loop with echo — common inspection pattern."""
        result = classify_expression('for f in *.txt; do echo "$f"; done', database)
        assert result.classification == Classification.READONLY

    def test_while_read_echo(self, database):
        """While read loop — common log processing pattern."""
        result = classify_expression('while read line; do echo "$line"; done < file.txt', database)
        assert result.classification == Classification.READONLY

    def test_if_then_cat(self, database):
        result = classify_expression("if [ -f file.txt ]; then cat file.txt; fi", database)
        assert result.classification == Classification.READONLY

    def test_sudo_with_pipe(self, database):
        # sudo cat /var/log/syslog -> DANGEROUS because /var/log/syslog is a system path
        # and sudo's min_classification is EXTERNAL_EFFECTS, which gets elevated to DANGEROUS
        result = classify_expression("sudo cat /var/log/syslog | grep error | tail -20", database)
        assert result.classification == Classification.DANGEROUS

    def test_git_log_pipe_xargs_show(self, database):
        """Git log piped to xargs for batch show."""
        result = classify_expression('git log --format="%H" | head -5 | xargs -I{} git show --stat {}', database)
        assert result.classification == Classification.READONLY

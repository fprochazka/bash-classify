"""Tests for sensitive-path detection.

Every test here pins the bundled denylist explicitly, so a user file in ~/.config cannot
change what they see.
"""

from __future__ import annotations

import pytest

from bash_classify import classify_expression
from bash_classify.classifier import iter_invocations
from bash_classify.models import Classification, Risk
from bash_classify.sensitive import (
    SensitivePathsError,
    get_default_sensitive_paths_file,
    get_user_sensitive_paths_file,
    load_sensitive_paths,
)


@pytest.fixture(scope="session")
def rules():
    return load_sensitive_paths(get_default_sensitive_paths_file())


def classify(expression: str, rules, database=None):
    return classify_expression(expression, database, sensitive_rules=rules)


def hits(expression: str, rules, database=None) -> list[tuple[str, str, str, str]]:
    result = classify(expression, rules, database)
    return [(h.token, h.rule, h.source, h.spelling) for h in result.sensitive_paths]


def rule_names(expression: str, rules, database=None) -> set[str]:
    return {h.rule for h in classify(expression, rules, database).sensitive_paths}


def assert_clean(expression: str, rules, database=None) -> None:
    """Assert that nothing was reported, at any depth."""
    result = classify(expression, rules, database)
    assert result.sensitive_paths == []
    for invocation, via in iter_invocations(result):
        assert invocation.sensitive_paths == [], f"{via} {invocation.command}"


class TestTheRiskFloor:
    def test_reading_a_private_key_stays_readonly_but_is_high_risk(self, rules, database) -> None:
        """The whole point: the floor must not inherit the `>= LOCAL_EFFECTS` guard that the
        system-path clamp has, or `cat ~/.ssh/id_rsa` goes back to being auto-approved."""
        result = classify("cat ~/.ssh/id_rsa", rules, database)
        assert result.classification == Classification.READONLY
        assert result.risk == Risk.HIGH
        assert result.commands[0].classification == Classification.READONLY
        assert result.commands[0].risk == Risk.HIGH

    def test_a_clean_command_keeps_its_risk(self, rules, database) -> None:
        result = classify("cat README.md", rules, database)
        assert result.risk == Risk.LOW
        assert result.sensitive_paths == []

    def test_classification_is_untouched_by_a_hit(self, rules, database) -> None:
        assert classify("cat < .env", rules, database).classification == Classification.READONLY

    def test_a_hit_on_one_command_of_a_pipeline_raises_the_expression(self, rules, database) -> None:
        result = classify("ls -la | grep x ; cat ~/.ssh/id_rsa", rules, database)
        assert result.risk == Risk.HIGH
        assert [c.risk for c in result.commands] == [Risk.LOW, Risk.LOW, Risk.HIGH]


class TestPathSpellings:
    @pytest.mark.parametrize(
        ("expression", "rule"),
        [
            ("cat ~/.ssh/id_rsa", "ssh"),
            ("cat /home/me/.ssh/id_rsa", "ssh"),
            ("cat ../.ssh/id_rsa", "ssh"),
            ("cat $HOME/.ssh/id_rsa", "ssh"),
            ('cat "$HOME"/.ssh/id_rsa', "ssh"),
            ("cat ${HOME}/.ssh/id_rsa", "ssh"),
            ("cat ~user/.ssh/id_rsa", "ssh"),
            ("cat ~/.aws/credentials", "aws-credentials"),
            ("cat ~/.config/gcloud/credentials.db", "gcloud"),
            ("cat ~/.kube/config", "kube"),
            ("cat .env", "dotenv"),
            ("cat .env.local", "dotenv"),
            ("cat /etc/shadow", "shadow"),
            ("cat /etc/sudoers", "shadow"),
            ("cat ~/.gnupg/secring.gpg", "gpg"),
            ("cat ~/.netrc", "netrc"),
            ("cat _netrc", "netrc"),
            ("cat ~/.npmrc", "npmrc-pypirc"),
            ("cat ~/.pypirc", "npmrc-pypirc"),
            ("cat ~/.docker/config.json", "docker-config"),
            ("cat /proc/1234/environ", "proc-environ"),
        ],
    )
    def test_the_denylist(self, expression, rule, rules, database) -> None:
        assert rule_names(expression, rules, database) == {rule}

    def test_quotes_inside_a_token_are_already_gone(self, rules, database) -> None:
        """The parser hands over one dequoted token, so nothing special is needed here. An
        implementation that worked on raw command text instead would miss both of these."""
        assert rule_names("cat ~/.s'sh'/id_rsa", rules, database) == {"ssh"}
        assert rule_names('cat ~/".ssh"/id_rsa', rules, database) == {"ssh"}


class TestHomeIsNotResolved:
    """A verdict must depend on the expression alone. Resolving `~` against the classifying
    process's own `$HOME` makes the answer depend on who runs the hook."""

    @pytest.mark.parametrize("home", ["/tmp/.ssh", "/home/someone", "/root/.aws", "/"])
    def test_the_verdict_does_not_move_with_home(self, home, rules, database, monkeypatch) -> None:
        monkeypatch.setenv("HOME", home)
        assert_clean("ls ~/projects", rules, database)
        assert_clean("cat $HOME/notes.md", rules, database)
        assert rule_names("cat ~/.ssh/id_rsa", rules, database) == {"ssh"}

    def test_the_reported_token_is_the_one_that_was_written(self, rules, database) -> None:
        assert hits("cat ~/.ssh/id_rsa", rules, database) == [("~/.ssh/id_rsa", "ssh", "argv", "literal")]


class TestTraversalSegments:
    """`.` and `..` are what a path traversal is made of. Leaving them in the segment list
    breaks the adjacency check that every multi-segment rule depends on."""

    @pytest.mark.parametrize(
        ("expression", "rule"),
        [
            ("cat /etc/./shadow", "shadow"),
            ("cat /etc//shadow", "shadow"),
            ("cat /etc/../etc/shadow", "shadow"),
            ("cat ~/.aws/./credentials", "aws-credentials"),
            ("cat ~/.aws/x/../credentials", "aws-credentials"),
            ("cat ~/./.config/gcloud/x", "gcloud"),
            ("cat ~/.config/x/../gcloud/y", "gcloud"),
            ("cat ~/.kube/./config", "kube"),
            ("cat ~/.kube/x/../config", "kube"),
            ("cat ~/.docker/./config.json", "docker-config"),
            ("cat ~/.docker/x/../config.json", "docker-config"),
            ("cat /proc/./1234/environ", "proc-environ"),
            ("cat /proc/1234/x/../environ", "proc-environ"),
        ],
    )
    def test_a_traversal_still_hits_the_rule(self, expression, rule, rules, database) -> None:
        assert rule_names(expression, rules, database) == {rule}

    @pytest.mark.parametrize(
        "expression",
        ["cat ~/./.ssh/id_rsa", "cat ~/x/../.ssh/id_rsa", "cat ~/../.ssh/id_rsa", "cat ./.env"],
    )
    def test_a_single_segment_rule_keeps_hitting(self, expression, rules, database) -> None:
        assert classify(expression, rules, database).sensitive_paths != []

    def test_a_traversal_out_of_the_directory_reads_nothing_in_it(self, rules, database) -> None:
        """`.ssh/../notes` opens `notes`. Reporting it would be a false positive."""
        assert_clean("cat .ssh/../notes", rules, database)
        assert_clean("cat ~/.aws/../notes", rules, database)


class TestBackslashReadings:
    """On POSIX an unquoted backslash is an escape, so `.s\\sh` opens `.ssh`."""

    @pytest.mark.parametrize(
        ("expression", "rule"),
        [
            (r"cat ~/.s\sh/id_rsa", "ssh"),
            (r"cat .en\v", "dotenv"),
            (r"cat /etc/sha\dow", "shadow"),
            (r"cat ~/.a\ws/credentials", "aws-credentials"),
        ],
    )
    def test_a_posix_escape_is_read_away(self, expression, rule, rules, database) -> None:
        found = [(h.rule, h.spelling) for h in classify(expression, rules, database).sensitive_paths]
        assert (rule, "posix_escape") in found

    def test_a_backslash_also_reads_as_a_windows_separator(self, rules, database) -> None:
        found = classify(r"type C:\Users\me\.ssh\id_rsa", rules, database).sensitive_paths
        assert [(h.rule, h.spelling) for h in found] == [("ssh", "windows")]


class TestGlobs:
    @pytest.mark.parametrize(
        ("expression", "rule"),
        [
            ("cat ~/.ss?/id_rsa", "ssh"),
            ("cat ~/.s*h/id_rsa", "ssh"),
            ("cat ~/.[s]sh/id_rsa", "ssh"),
            ("cat ~/.[!x]sh/id_rsa", "ssh"),
            ("cat ~/.[^x]sh/id_rsa", "ssh"),
            ("cat ~/.[^xyz]sh/id_rsa", "ssh"),
            ("cat .en?", "dotenv"),
            ("cat .e*", "dotenv"),
        ],
    )
    def test_a_glob_that_expands_to_the_real_file_is_caught(self, expression, rule, rules, database) -> None:
        found = [(h.rule, h.spelling) for h in classify(expression, rules, database).sensitive_paths]
        assert found == [(rule, "glob")]

    @pytest.mark.parametrize("expression", ["ls *", "cat .*", "ls ?", "ls **", "ls */*"])
    def test_a_glob_below_the_two_character_floor_is_ignored(self, expression, rules, database) -> None:
        """Without the floor every one of these matches every rule at once, and a gate that
        fires on `ls *` is a gate someone switches off."""
        assert_clean(expression, rules, database)

    @pytest.mark.parametrize(
        "expression",
        [
            "cat ~/.[a^b]sh/id_rsa",  # a '^' that is not leading is an ordinary member
            "cat ~/.[^]sh/id_rsa",  # the group never closes, so '[' is literal
            "cat ~/.[sh/id_rsa",  # likewise
            "cat ~/.[!s]sh/id_rsa",  # excludes the very character that would match
        ],
    )
    def test_a_bracket_that_cannot_open_the_file_is_not_a_hit(self, expression, rules, database) -> None:
        assert_clean(expression, rules, database)


class TestSegmentBoundaries:
    @pytest.mark.parametrize("expression", ["cat .gitignore", "ls .github", "cat .github/workflows/ci.yml"])
    def test_a_longer_segment_is_not_the_rule(self, expression, rules, database) -> None:
        assert_clean(expression, rules, database)

    def test_argv_tokens_are_never_joined(self, rules, database) -> None:
        """`.aws/credentials` is one token. Two separate words are two paths."""
        assert_clean("aws credentials list", rules, database)

    def test_a_dotenv_rule_does_not_eat_a_longer_name(self, rules, database) -> None:
        assert_clean("cat .environment", rules, database)


class TestTemplateExemptions:
    @pytest.mark.parametrize(
        "expression",
        [
            "cat .env.example",
            "cat .env.sample",
            "cat .env.template",
            "cat .env.dist",
            "cat .env.defaults",
            "git add .env.example",
            "diff .env.example .env.template",
        ],
    )
    def test_a_committed_template_is_not_a_secret(self, expression, rules, database) -> None:
        """These are the names projects commit with placeholder values. A gate that fires
        every time somebody opens one is a gate they turn off."""
        assert_clean(expression, rules, database)

    @pytest.mark.parametrize(
        "expression",
        ["cat .env", "cat .env.local", "cat .env.production", "cat .env.test", "cat ~/.env.staging"],
    )
    def test_a_real_dotenv_still_hits(self, expression, rules, database) -> None:
        assert rule_names(expression, rules, database) == {"dotenv"}

    def test_the_exemption_is_per_token(self, rules, database) -> None:
        """Copying a template into a real dotenv writes a real dotenv."""
        assert hits("cp .env.example .env.local", rules, database) == [(".env.local", "dotenv", "argv", "literal")]

    def test_a_glob_cannot_exempt_itself(self, rules, database) -> None:
        """`fnmatch(".env.example", ".e*")` is true, so an exemption read backwards would let
        `cat .e*` walk out of the rule it just matched."""
        assert rule_names("cat .e*", rules, database) == {"dotenv"}


class TestDroppedRules:
    """A file that is merely uninteresting to read does not belong on the denylist."""

    @pytest.mark.parametrize(
        "expression", ["cat .git/config", "cat ~/.gitconfig", "git config --list", "cat ~/.aws/config"]
    )
    def test_a_config_that_holds_no_credential_is_clean(self, expression, rules, database) -> None:
        assert_clean(expression, rules, database)


class TestRedirects:
    def test_an_input_redirect_reads_the_file(self, rules, database) -> None:
        assert hits("cat < .env", rules, database) == [(".env", "dotenv", "redirect_read", "literal")]

    @pytest.mark.parametrize(
        "expression",
        [
            "echo k > ~/.ssh/authorized_keys",
            "echo k >> ~/.ssh/authorized_keys",
            "echo k >| ~/.ssh/authorized_keys",
            "echo k 1> ~/.ssh/authorized_keys",
            "echo k 1>| ~/.ssh/authorized_keys",
            "echo k 1>> ~/.ssh/authorized_keys",
            "echo k 2> ~/.ssh/authorized_keys",
            "echo k 3> ~/.ssh/authorized_keys",
            "echo k 4>> ~/.ssh/authorized_keys",
            "echo k &> ~/.ssh/authorized_keys",
            "echo k &>> ~/.ssh/authorized_keys",
            "echo k >& ~/.ssh/authorized_keys",
        ],
    )
    def test_every_write_operator_counts(self, expression, rules, database) -> None:
        """`1>` is byte-for-byte `>`, and bash allows the descriptor on every write form."""
        assert hits(expression, rules, database) == [("~/.ssh/authorized_keys", "ssh", "redirect_write", "literal")]

    @pytest.mark.parametrize(
        "expression",
        [
            "echo k > ~/.ssh/authorized_keys",
            "echo k >| ~/.ssh/authorized_keys",
            "echo k 1> ~/.ssh/authorized_keys",
            "echo k 2>> ~/.ssh/authorized_keys",
            "echo k &>> ~/.ssh/authorized_keys",
            "echo k >& ~/.ssh/authorized_keys",
        ],
    )
    def test_the_scan_and_the_classifier_read_the_same_operator(self, expression, rules, database) -> None:
        """Both axes must move together. A form the scan calls a write but the classifier
        calls no write reports a credential hit on a READONLY command."""
        result = classify(expression, rules, database)
        assert result.classification == Classification.LOCAL_EFFECTS
        assert result.risk == Risk.HIGH
        assert result.write_paths == ["~/.ssh/authorized_keys"]

    def test_a_heredoc_delimiter_is_not_a_path(self, rules, database) -> None:
        """A `<<` target is the delimiter word. Scanning it reports a hit on a heredoc whose
        delimiter happens to be named after a rule."""
        assert_clean("cat <<.env\nhello\n.env", rules, database)

    def test_a_herestring_is_text_and_a_descriptor_is_a_number(self, rules, database) -> None:
        assert_clean("cat <<< .env", rules, database)
        assert_clean("cat <& 3", rules, database)

    def test_file_redirect_after_heredoc_opener_is_scanned(self, rules, database) -> None:
        """`cat <<EOF > ~/.ssh/authorized_keys` must hit just like `cat > ~/.ssh/authorized_keys <<EOF`.

        The grammar nests the file redirect inside the heredoc_redirect node, so a parser
        that only reads the `<<` sibling on redirected_statement loses the write target.
        """
        assert hits("cat <<EOF > ~/.ssh/authorized_keys\nbody\nEOF", rules, database) == [
            ("~/.ssh/authorized_keys", "ssh", "redirect_write", "literal")
        ]

    def test_heredoc_body_is_not_scanned_for_sensitive_paths(self, rules, database) -> None:
        """The heredoc body is data, not a redirect target. A sensitive path mentioned inside
        the body must not produce a hit."""
        assert_clean("cat <<EOF > /tmp/x\n~/.ssh/authorized_keys\nEOF", rules, database)


class TestEnvironmentDumps:
    @pytest.mark.parametrize("expression", ["env", "printenv", "/usr/bin/printenv", "env | grep KEY"])
    def test_a_bare_dump_is_a_hit(self, expression, rules, database) -> None:
        assert "env-dump" in rule_names(expression, rules, database)

    @pytest.mark.parametrize("expression", ["env FOO=1 make", "printenv PATH", "env -C /tmp make"])
    def test_a_dump_with_positionals_is_not_one(self, expression, rules, database) -> None:
        assert "env-dump" not in rule_names(expression, rules, database)

    def test_the_dump_carries_the_binary_as_written(self, rules, database) -> None:
        assert hits("/usr/bin/printenv", rules, database) == [("/usr/bin/printenv", "env-dump", "env_dump", "literal")]


class TestSecretVariableNames:
    @pytest.mark.parametrize(
        "expression",
        [
            "echo $ANTHROPIC_API_KEY",
            "echo ${GITHUB_TOKEN}",
            "curl -H $AUTH_TOKEN https://example.com",
            "echo $DB_PASSWORD",
            "echo $GOOGLE_APPLICATION_CREDENTIALS",
            "echo $APIKEY",
        ],
    )
    def test_a_dollar_form_counts_under_any_command(self, expression, rules, database) -> None:
        assert "secret-env-var" in rule_names(expression, rules, database)

    @pytest.mark.parametrize(
        "expression",
        ["printenv ANTHROPIC_API_KEY", "env API_KEY", "/usr/bin/printenv GITHUB_TOKEN"],
    )
    def test_a_bare_name_counts_for_a_command_that_reads_variable_names(self, expression, rules, database) -> None:
        assert "secret-env-var" in rule_names(expression, rules, database)

    @pytest.mark.parametrize(
        "expression",
        [
            "grep -rn TOKEN src",
            "grep -r API_KEY .",
            "rg SECRET -n",
            "git log --grep TOKEN",
            "ls SECRET",
            "echo KEY",
            "echo API_KEY",
        ],
    )
    def test_a_bare_name_is_a_search_string_everywhere_else(self, expression, rules, database) -> None:
        """A bare all-caps word is a variable name to `printenv` and a pattern to `grep`.
        Reporting both is what makes somebody switch the gate off."""
        assert "secret-env-var" not in rule_names(expression, rules, database)

    @pytest.mark.parametrize(
        "expression",
        ["printenv PATH", "echo $HOME", "echo $PWD", "echo monkey", "echo MONKEY", "printenv KEYBOARD", "make KEY=1"],
    )
    def test_an_ordinary_name_is_not(self, expression, rules, database) -> None:
        assert "secret-env-var" not in rule_names(expression, rules, database)


class TestFalsePositives:
    @pytest.mark.parametrize(
        "expression",
        [
            "ls *",
            "cat .*",
            "git status",
            "grep -rn foo src",
            "grep -rn TOKEN src",
            "env FOO=1 make",
            "printenv PATH",
            "cat .gitignore",
            "ls .github",
            "cat .git/config",
            "cat .env.example",
            "ls -la",
            "npm install",
            "docker ps",
            "kubectl get pods",
            "find . -name '*.py'",
            "python -m pytest tests/",
        ],
    )
    def test_routine_commands_stay_clean(self, expression, rules, database) -> None:
        assert_clean(expression, rules, database)


class TestEveryDepth:
    @pytest.mark.parametrize(
        "expression",
        [
            "sudo cat ~/.ssh/id_rsa",
            "cat ~/.ssh/id_rsa | base64",
            "xargs cat ~/.ssh/id_rsa",
            "env cat ~/.ssh/id_rsa",
            "timeout 5 cat ~/.ssh/id_rsa",
            "sh -c 'cat ~/.ssh/id_rsa'",
            'sh -c "sh -c \\"cat ~/.ssh/id_rsa\\""',
            "find . -name x -exec cat /etc/shadow ;",
            "eval 'cat ~/.ssh/id_rsa'",
        ],
    )
    def test_a_hit_at_any_depth_reaches_the_top(self, expression, rules, database) -> None:
        result = classify(expression, rules, database)
        assert result.sensitive_paths != []
        assert result.risk == Risk.HIGH

    def test_a_wrapper_reports_what_it_hides(self, rules, database) -> None:
        result = classify("sudo cat ~/.ssh/id_rsa", rules, database)
        sudo = result.commands[0]
        inner = sudo.inner_commands[0]
        assert [h.rule for h in inner.sensitive_paths] == ["ssh"]
        assert [h.rule for h in sudo.sensitive_paths] == ["ssh"]
        assert sudo.risk == Risk.HIGH

    def test_each_invocation_reports_only_what_it_and_its_children_carry(self, rules, database) -> None:
        result = classify("sudo cat ~/.ssh/id_rsa | grep -c ''", rules, database)
        by_command = {tuple(i.command): [h.rule for h in i.sensitive_paths] for i, _ in iter_invocations(result)}
        assert by_command[("sudo",)] == ["ssh"]
        assert by_command[("cat",)] == ["ssh"]
        assert by_command[("grep",)] == []


class TestOutOfScope:
    """Spellings that defeat a static matcher. Pinned so nobody reads the feature as
    stronger than it is; SPEC.md names all of them."""

    @pytest.mark.parametrize(
        "expression",
        [
            'P=~/.ssh/id_rsa; cat "$P"',
            "cat $(find ~ -name id_rsa)",
            "base64 -d <<< L2hvbWUvbWUvLnNzaC9pZF9yc2E=",
            "cat .*",
        ],
    )
    def test_these_are_not_detected(self, expression, rules, database) -> None:
        assert_clean(expression, rules, database)

    def test_a_substitution_that_spells_the_path_is_still_seen(self, rules, database) -> None:
        """Not a guarantee. The token happens to carry the segments, so the argv scan reads
        them; a substitution that computes the path carries nothing to read."""
        assert rule_names("cat $(echo ~/.ssh/id_rsa)", rules, database) == {"ssh"}

    def test_a_token_that_only_mentions_a_path_is_a_hit(self, rules, database) -> None:
        """The known false positive. Separating a path that is opened from one that is
        quoted needs per-command argument knowledge, which is out of scope."""
        assert rule_names('git commit -m "document ~/.ssh/config setup"', rules, database) == {"ssh"}


class TestLoading:
    def test_the_bundled_file_carries_the_expected_rules(self, rules) -> None:
        assert {rule.name for rule in rules} == {
            "ssh",
            "aws-credentials",
            "gcloud",
            "kube",
            "dotenv",
            "shadow",
            "gpg",
            "netrc",
            "npmrc-pypirc",
            "docker-config",
            "proc-environ",
        }

    def test_a_user_file_extends_the_bundled_set(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "sensitive-paths.yaml").write_text("rules:\n  - name: company-vault\n    paths: [.acme/vault]\n")
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path))
        loaded = load_sensitive_paths()
        assert {rule.name for rule in loaded} > {"ssh"}
        assert "company-vault" in {rule.name for rule in loaded}
        assert rule_names("cat ~/.acme/vault", loaded) == {"company-vault"}

    def test_a_user_rule_replaces_the_bundled_one_of_the_same_name(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "sensitive-paths.yaml").write_text("rules:\n  - name: dotenv\n    paths: [.env.production]\n")
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path))
        loaded = load_sensitive_paths()
        assert rule_names("cat .env", loaded) == set()
        assert rule_names("cat .env.production", loaded) == {"dotenv"}

    def test_a_user_rule_can_carry_its_own_exemptions(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "sensitive-paths.yaml").write_text(
            "rules:\n  - name: vault\n    paths: [.acme/vault]\n    except_paths: [.acme/vault/README]\n"
        )
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path))
        loaded = load_sensitive_paths()
        assert rule_names("cat ~/.acme/vault/token", loaded) == {"vault"}
        assert rule_names("cat ~/.acme/vault/README", loaded) == set()

    def test_the_user_file_location_follows_the_config_dir(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path))
        assert get_user_sensitive_paths_file() == tmp_path / "sensitive-paths.yaml"

    def test_no_user_file_means_the_bundled_set(self, tmp_path, monkeypatch, rules) -> None:
        monkeypatch.setenv("BASH_CLASSIFY_CONFIG_DIR", str(tmp_path))
        assert load_sensitive_paths() == rules

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ("[]", "top level must be a mapping"),
            ("paths: []", "unknown top-level key"),
            ("rules: []", "must be a non-empty list"),
            ("rules:\n  - name: a\n", "'paths' must be a non-empty list"),
            ("rules:\n  - paths: [.x]\n", "'name' must be a non-empty string"),
            ("rules:\n  - name: a\n    paths: [.x]\n    extra: 1\n", r"unknown key\(s\): extra"),
            ("rules:\n  - name: a\n    paths: ['/']\n", "no segments to match"),
            ("rules:\n  - name: a\n    paths: [.x]\n    except_paths: []\n", "'except_paths' must be a non-empty list"),
            ("rules:\n  - name: a\n    paths: [.x]\n    except_paths: ['/']\n", r"in 'except_paths' has no segments"),
            ("rules:\n  - name: a\n    paths: [.x]\n  - name: a\n    paths: [.y]\n", "duplicate rule name"),
        ],
    )
    def test_a_broken_file_names_the_problem(self, tmp_path, content, message) -> None:
        broken = tmp_path / "sensitive-paths.yaml"
        broken.write_text(content)
        with pytest.raises(SensitivePathsError, match=message):
            load_sensitive_paths(broken)

    def test_a_missing_explicit_file_is_an_error(self, tmp_path) -> None:
        with pytest.raises(SensitivePathsError, match="cannot read sensitive-paths file"):
            load_sensitive_paths(tmp_path / "nope.yaml")

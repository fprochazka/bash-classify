"""Tests for the rules format and the match engine.

These load the command database from the repo's own `commands/` directory rather than
through `load_database()`, so a user override in `~/.config` cannot change the result.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bash_classify.database import load_database
from bash_classify.models import CommandDef
from bash_classify.rules import (
    Match,
    Rule,
    RulesError,
    argument_tokens,
    load_rules,
    match_expression,
)

COMMANDS_DIR = Path(__file__).parent.parent / "src" / "bash_classify" / "commands"


@pytest.fixture(scope="module")
def db() -> dict[str, CommandDef]:
    return load_database(COMMANDS_DIR)


def _rule(name: str = "r", command: list[str] | None = None, **kwargs) -> Rule:
    return Rule(name=name, command=command or ["glab", "mr", "note"], **kwargs)


def _names(matches: list[Match]) -> list[str]:
    return [m.rule for m in matches]


class TestCommandPrefixMatching:
    def test_exact_path_matches(self, db) -> None:
        result = match_expression("glab mr note 42 -m hi", [_rule()], db)
        assert _names(result.matches) == ["r"]
        assert result.matches[0].command == ["glab", "mr", "note"]
        assert result.matches[0].argv == ["glab", "mr", "note", "42", "-m", "hi"]
        assert result.matches[0].via == []

    def test_longer_path_matches_the_prefix(self, db) -> None:
        """A rule on [glab, mr] matches `glab mr view` too."""
        result = match_expression("glab mr view 42", [_rule(command=["glab", "mr"])], db)
        assert _names(result.matches) == ["r"]

    def test_shorter_path_does_not_match(self, db) -> None:
        result = match_expression("glab mr", [_rule()], db)
        assert result.matches == []

    def test_different_subcommand_does_not_match(self, db) -> None:
        result = match_expression("glab mr view 42", [_rule()], db)
        assert result.matches == []

    def test_global_option_before_the_subcommand_still_matches(self, db) -> None:
        """`command` is the resolved path, so a global option does not hide it."""
        result = match_expression("glab --repo group/project mr note 42 -m hi", [_rule()], db)
        assert _names(result.matches) == ["r"]

    def test_absolute_binary_path_still_matches(self, db) -> None:
        result = match_expression("/usr/bin/glab mr note 42 -m hi", [_rule()], db)
        assert _names(result.matches) == ["r"]

    def test_no_rules_means_no_matches(self, db) -> None:
        result = match_expression("glab mr note 42", [], db)
        assert result.matches == []
        assert result.parse_warnings == []


class TestExcept:
    def test_excluded_path_does_not_match(self, db) -> None:
        rule = _rule(except_=[["glab", "mr", "note", "list"]])
        result = match_expression("glab mr note list 42", [rule], db)
        assert result.matches == []

    def test_sibling_of_the_excluded_path_still_matches(self, db) -> None:
        rule = _rule(except_=[["glab", "mr", "note", "list"]])
        result = match_expression("glab mr note 42 -m hi", [rule], db)
        assert _names(result.matches) == ["r"]

    def test_except_is_also_a_prefix(self, db) -> None:
        rule = _rule(command=["glab", "mr"], except_=[["glab", "mr", "note"]])
        assert match_expression("glab mr note 42", [rule], db).matches == []
        assert _names(match_expression("glab mr view 42", [rule], db).matches) == ["r"]


class TestAnyOption:
    def _view_rule(self, options: list[str]) -> Rule:
        return Rule(name="view", command=["glab", "mr", "view"], any_option=options)

    def test_long_option_present(self, db) -> None:
        result = match_expression("glab mr view 42 --comments", [self._view_rule(["--comments", "-c"])], db)
        assert _names(result.matches) == ["view"]

    def test_short_option_present(self, db) -> None:
        result = match_expression("glab mr view -c 42", [self._view_rule(["--comments", "-c"])], db)
        assert _names(result.matches) == ["view"]

    def test_declared_cluster_expands(self, db) -> None:
        """`-wc` carries `-c`, because both characters are declared on `glab mr view`."""
        result = match_expression("glab mr view -wc 42", [self._view_rule(["--comments", "-c"])], db)
        assert _names(result.matches) == ["view"]

    def test_equals_form_matches_the_long_option(self, db) -> None:
        result = match_expression("glab mr view 42 --comments=true", [self._view_rule(["--comments"])], db)
        assert _names(result.matches) == ["view"]

    def test_option_absent_does_not_match(self, db) -> None:
        result = match_expression("glab mr view 42 -F json", [self._view_rule(["--comments", "-c"])], db)
        assert result.matches == []

    def test_after_end_of_options_marker_is_a_positional(self, db) -> None:
        """glab stops flag parsing at `--` too, so this is not the option."""
        result = match_expression("glab mr view -- 42 --comments", [self._view_rule(["--comments", "-c"])], db)
        assert result.matches == []


class TestAnyArgMatches:
    def _api_rule(self, pattern: str) -> Rule:
        return Rule(name="api", command=["glab", "api"], any_arg_matches=re.compile(pattern))

    def test_matches_a_positional(self, db) -> None:
        rule = self._api_rule(r"merge_requests/[^/?]+/(discussions|notes)(/|\?|$)")
        result = match_expression("glab api projects/42/merge_requests/123/discussions --paginate", [rule], db)
        assert _names(result.matches) == ["api"]

    def test_matches_an_option_value(self, db) -> None:
        rule = self._api_rule(r"^group/project$")
        result = match_expression("glab api --hostname group/project projects/42", [rule], db)
        assert _names(result.matches) == ["api"]

    def test_matches_an_option_flag(self, db) -> None:
        rule = self._api_rule(r"^--paginate$")
        result = match_expression("glab api projects/42 --paginate", [rule], db)
        assert _names(result.matches) == ["api"]

    def test_never_matches_argv_zero(self, db) -> None:
        rule = self._api_rule(r"^glab$")
        result = match_expression("glab api projects/42", [rule], db)
        assert result.matches == []

    def test_never_matches_a_subcommand_word(self, db) -> None:
        """A rule on [glab, mr] must not see `view`, the word that resolved the command."""
        rule = Rule(name="mr", command=["glab", "mr"], any_arg_matches=re.compile(r"^view$"))
        result = match_expression("glab mr view 42", [rule], db)
        assert result.matches == []

    def test_non_matching_pattern(self, db) -> None:
        rule = self._api_rule(r"merge_requests/[^/?]+/(discussions|notes)(/|\?|$)")
        result = match_expression("glab api projects/42/merge_requests/123 --paginate", [rule], db)
        assert result.matches == []

    def test_argument_tokens_drops_binary_and_subcommand_words(self, db) -> None:
        result = match_expression("glab mr view 42 -F json", [], db)
        # match_expression with no rules still classified it; recompute the token set.
        from bash_classify.classifier import classify_expression

        invocation = classify_expression("glab mr view 42 -F json", db).commands[0]
        assert argument_tokens(invocation) == ["42", "-F", "json"]
        assert result.matches == []


class TestConditionsCombine:
    def test_all_conditions_must_hold(self, db) -> None:
        import re

        rule = Rule(
            name="both",
            command=["glab", "mr", "view"],
            any_option=["--comments"],
            any_arg_matches=re.compile(r"^42$"),
        )
        assert _names(match_expression("glab mr view 42 --comments", [rule], db).matches) == ["both"]
        assert match_expression("glab mr view 43 --comments", [rule], db).matches == []
        assert match_expression("glab mr view 42 -F json", [rule], db).matches == []

    def test_rules_are_independent(self, db) -> None:
        rules = [
            Rule(name="note", command=["glab", "mr", "note"]),
            Rule(name="view", command=["glab", "mr", "view"]),
        ]
        result = match_expression("glab mr note 42 -m hi && glab mr view 42", rules, db)
        assert _names(result.matches) == ["note", "view"]

    def test_one_invocation_can_match_several_rules(self, db) -> None:
        rules = [
            Rule(name="broad", command=["glab", "mr"]),
            Rule(name="narrow", command=["glab", "mr", "note"]),
        ]
        result = match_expression("glab mr note 42 -m hi", rules, db)
        assert _names(result.matches) == ["broad", "narrow"]
        assert {m.command[0] for m in result.matches} == {"glab"}


class TestDepthAndVia:
    RULE = Rule(name="note", command=["glab", "mr", "note"])

    def _match_one(self, expression: str, db) -> Match:
        result = match_expression(expression, [self.RULE], db)
        assert len(result.matches) == 1, f"{expression!r} -> {result.matches}"
        assert result.parse_warnings == []
        return result.matches[0]

    def test_top_level(self, db) -> None:
        assert self._match_one("glab mr note 42 -m hi", db).via == []

    def test_sudo(self, db) -> None:
        assert self._match_one("sudo glab mr note 42 -m hi", db).via == ["sudo"]

    def test_timeout(self, db) -> None:
        assert self._match_one("timeout 5 glab mr note 42 -m hi", db).via == ["timeout"]

    def test_env_assignment_prefix_is_not_a_wrapper(self, db) -> None:
        """`VAR=x cmd` strips the assignment; the command stays top level."""
        assert self._match_one("GITLAB_HOST=gitlab.example.com glab mr note 42 -m hi", db).via == []

    def test_env_command(self, db) -> None:
        assert self._match_one("env FOO=1 glab mr note 42 -m hi", db).via == ["env"]

    def test_xargs(self, db) -> None:
        assert self._match_one("echo 42 | xargs -I{} glab mr note {} -m hi", db).via == ["xargs"]

    def test_bash_c(self, db) -> None:
        assert self._match_one("bash -c 'glab mr note 42 -m hi'", db).via == ["bash"]

    def test_find_exec(self, db) -> None:
        assert self._match_one("find . -name '*.md' -exec glab mr note 42 -m hi \\;", db).via == ["find"]

    def test_eval(self, db) -> None:
        assert self._match_one('eval "glab mr note 42 -m hi"', db).via == ["eval"]

    def test_exec(self, db) -> None:
        assert self._match_one("exec glab mr note 42 -m hi", db).via == ["exec"]

    def test_command_substitution_is_top_level(self, db) -> None:
        assert self._match_one("OUT=$(glab mr note 42 -m hi)", db).via == []

    def test_nested_wrappers_report_outermost_first(self, db) -> None:
        match = self._match_one("sudo timeout 5 glab mr note 42 -m hi", db)
        assert match.via == ["sudo", "timeout"]


class TestTextMentionsDoNotMatch:
    RULES = [
        Rule(name="note", command=["glab", "mr", "note"]),
        Rule(name="view", command=["glab", "mr", "view"], any_option=["--comments"]),
    ]

    def _no_match(self, expression: str, db) -> None:
        result = match_expression(expression, self.RULES, db)
        assert result.matches == [], f"{expression!r} matched {result.matches}"

    def test_echo(self, db) -> None:
        self._no_match('echo "do not use glab mr note, use glab-discussion"', db)

    def test_printf(self, db) -> None:
        self._no_match("printf '%s' 'glab mr view --comments is blocked'", db)

    def test_comment(self, db) -> None:
        self._no_match("# glab mr note is blocked\necho ok", db)

    def test_git_commit_message(self, db) -> None:
        self._no_match('git commit -m "docs: explain that glab mr note is blocked"', db)

    def test_grep_pattern(self, db) -> None:
        self._no_match('grep -rn "glab mr note" docs/', db)

    def test_heredoc_body(self, db) -> None:
        self._no_match(
            "cat > /tmp/work/brief.md <<'EOF'\n"
            "`glab mr view --comments` and `glab mr note` are blocked by a wrapper.\n"
            "EOF\n"
            "echo written",
            db,
        )

    def test_heredoc_body_then_a_real_call_still_matches(self, db) -> None:
        result = match_expression(
            "cat > /tmp/work/brief.md <<'EOF'\nmentions glab mr note in prose\nEOF\nglab mr note 42 -m hi",
            self.RULES,
            db,
        )
        assert _names(result.matches) == ["note"]


class TestParseWarnings:
    def test_always_present_and_empty_on_a_clean_parse(self, db) -> None:
        result = match_expression("glab mr note 42 -m hi", [Rule(name="n", command=["glab"])], db)
        assert result.parse_warnings == []

    def test_propagated_for_a_broken_expression(self, db) -> None:
        result = match_expression("glab mr note 42 -m hi; if then fi (", [Rule(name="n", command=["glab"])], db)
        assert result.parse_warnings
        assert "syntax error" in result.parse_warnings[0]


class TestLoadRules:
    def _write(self, tmp_path: Path, text: str) -> Path:
        path = tmp_path / "rules.yaml"
        path.write_text(text)
        return path

    def test_full_rule_round_trip(self, tmp_path: Path) -> None:
        path = self._write(
            tmp_path,
            "rules:\n"
            "  - name: mr-note\n"
            "    command: [glab, mr, note]\n"
            "    except: [[glab, mr, note, list]]\n"
            "    any_option: [--comments, -c]\n"
            "    any_arg_matches: 'merge_requests/[^/?]+/notes'\n",
        )
        rules = load_rules(path)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.name == "mr-note"
        assert rule.command == ["glab", "mr", "note"]
        assert rule.except_ == [["glab", "mr", "note", "list"]]
        assert rule.any_option == ["--comments", "-c"]
        assert rule.any_arg_matches is not None
        assert rule.any_arg_matches.search("merge_requests/1/notes")

    def test_minimal_rule(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n")
        rule = load_rules(path)[0]
        assert rule.except_ == []
        assert rule.any_option == []
        assert rule.any_arg_matches is None

    def test_missing_file(self, tmp_path: Path) -> None:
        missing = tmp_path / "nope.yaml"
        with pytest.raises(RulesError, match=r"nope\.yaml: cannot read rules file"):
            load_rules(missing)

    def test_not_a_mapping(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "- just\n- a\n- list\n")
        with pytest.raises(RulesError, match="top level must be a mapping"):
            load_rules(path)

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules: [\n")
        with pytest.raises(RulesError, match="not valid YAML"):
            load_rules(path)

    def test_missing_rules_key(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "other: 1\n")
        with pytest.raises(RulesError, match="unknown top-level key"):
            load_rules(path)

    def test_empty_rules_list(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules: []\n")
        with pytest.raises(RulesError, match="'rules' must be a non-empty list"):
            load_rules(path)

    def test_rule_is_not_a_mapping(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - just-a-string\n")
        with pytest.raises(RulesError, match="rule #0: must be a mapping"):
            load_rules(path)

    def test_unknown_rule_key(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n    all_options: [-c]\n")
        with pytest.raises(RulesError, match="rule 'n': unknown key\\(s\\): all_options"):
            load_rules(path)

    def test_missing_name(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - command: [glab]\n")
        with pytest.raises(RulesError, match="rule #0: 'name' must be a non-empty string"):
            load_rules(path)

    def test_duplicate_name(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n  - name: n\n    command: [git]\n")
        with pytest.raises(RulesError, match="rule 'n': duplicate rule name"):
            load_rules(path)

    def test_missing_command(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n")
        with pytest.raises(RulesError, match="rule 'n': 'command' must be a non-empty list"):
            load_rules(path)

    def test_empty_command(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: []\n")
        with pytest.raises(RulesError, match="rule 'n': 'command' must be a non-empty list"):
            load_rules(path)

    def test_command_with_a_non_string(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab, 42]\n")
        with pytest.raises(RulesError, match="'command' entries must be non-empty strings"):
            load_rules(path)

    def test_except_not_a_list_of_paths(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n    except: [glab]\n")
        with pytest.raises(RulesError, match="'except entry' must be a non-empty list"):
            load_rules(path)

    def test_any_option_without_a_dash(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n    any_option: [comments]\n")
        with pytest.raises(RulesError, match="must be strings starting with '-'"):
            load_rules(path)

    def test_any_option_empty(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n    any_option: []\n")
        with pytest.raises(RulesError, match="'any_option' must be a non-empty list"):
            load_rules(path)

    def test_explicit_null_is_rejected_like_the_schema_rejects_it(self, tmp_path: Path) -> None:
        """`except:` with no value is YAML null, not an omitted key."""
        for key, message in [
            ("except", "'except' must be a list of command paths"),
            ("any_option", "'any_option' must be a non-empty list"),
            ("any_arg_matches", "'any_arg_matches' must be a non-empty string"),
        ]:
            path = self._write(tmp_path, f"rules:\n  - name: n\n    command: [glab]\n    {key}:\n")
            with pytest.raises(RulesError, match=re.escape(message)):
                load_rules(path)

    def test_bad_regex(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules:\n  - name: n\n    command: [glab]\n    any_arg_matches: '('\n")
        with pytest.raises(RulesError, match="'any_arg_matches' is not a valid Python regex"):
            load_rules(path)

    def test_error_message_names_the_file(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "rules: []\n")
        with pytest.raises(RulesError) as excinfo:
            load_rules(path)
        assert str(path) in str(excinfo.value)

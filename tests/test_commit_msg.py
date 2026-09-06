"""The commit-message checker (`tools/commit_msg.py`).

It runs on every commit anyone makes, so a false *rejection* is worse than a missed violation:
it blocks work and teaches people to reach for `--no-verify`, after which the rule enforces
nothing at all. The cases below are therefore weighted towards what must keep passing — real
subjects from this repository's own history, `git commit -v` messages with a diff attached,
merges and reverts.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# `tools/` is not part of the package, so put the repository root on the path ourselves —
# otherwise this file only imports when pytest happens to have done it for us.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.commit_msg import EXAMPLE, check, clean, main

# Subjects taken from `git log`: whatever else changes, these must not start failing.
REAL = [
    "feat(loader): collapse duplicate rules, candidates, checks and events on load",
    "feat(parser): created a terraform state file parser to load for account",
    "chore(examples): refacto of the examples into proper files",
    "feat(env): load the account from Terraform (terraform show -json or *.tf.json)",
    "docs: updated the README and added a changelog file",
    "chore: point example paths at the restructured examples/ layout",
]


@pytest.mark.parametrize("message", REAL)
def test_the_history_this_repository_already_has_still_passes(message):
    assert check(message) == []


@pytest.mark.parametrize("kind", ["feat", "fix", "docs", "test", "refactor", "perf", "chore", "ci", "build"])
def test_every_allowed_type(kind):
    assert check(f"{kind}: do the thing") == []


def test_a_scope_and_a_breaking_change_marker_are_both_allowed():
    assert check("fix(smt/coverage): stop pruning the last atom") == []
    assert check("feat!: rename the account schema") == []
    assert check("feat(env)!: rename the account schema") == []


# --- what it must reject ------------------------------------------------------------------


def test_a_message_with_no_type_is_refused():
    (problem,) = check("added stuff")
    assert "type(scope): what and why" in problem


def test_an_unknown_type_is_named_along_with_the_ones_that_work():
    (problem,) = check("wip: something")
    assert "'wip'" in problem and "feat" in problem


def test_a_subject_is_required():
    assert check("feat: ") != []
    assert check("feat:") != []


def test_the_subject_is_lower_case_and_has_no_full_stop():
    problems = check("feat: Adds a thing.")
    assert any("full stop" in p for p in problems)
    assert any("lower case" in p for p in problems)


def test_a_long_header_is_refused_with_the_length_in_the_message():
    problems = check("feat: " + "x" * 200)
    assert any("the limit is 100" in p and "206 characters" in p for p in problems)


def test_one_line_means_one_line():
    (problem,) = check("feat: add a thing\n\nAnd here is a long explanation.")
    assert "one line" in problem


@pytest.mark.parametrize(
    "trailer",
    [
        "Co-authored-by: Someone <s@example.com>",
        "Signed-off-by: Someone <s@example.com>",
        "Claude-Session: https://example.com/x",
        "Generated-with: a tool",
    ],
)
def test_no_trailers(trailer):
    problems = check(f"feat: add a thing\n\n{trailer}")
    assert any("no trailers" in p and trailer.split(":")[0] in p for p in problems)


def test_the_reason_is_specific_enough_to_act_on():
    """Every problem names the rule; a bare 'invalid commit message' teaches nobody anything."""
    for problem in check("Wip: Added stuff.\n\nSigned-off-by: X <x@y.z>"):
        assert len(problem) > 20 and not problem.startswith("invalid")


# --- what it must not touch ---------------------------------------------------------------


def test_a_merge_commit_is_left_alone():
    assert check("Merge branch 'dev' into feature") == []


def test_a_revert_is_left_alone_however_git_wrote_it():
    assert check("Revert \"feat: add a thing\"\n\nThis reverts commit abc123.") == []
    assert check("revert: feat: add a thing\n\nThis reverts commit abc123.") == []


def test_fixup_and_squash_commits_pass_because_rebase_will_absorb_them():
    assert check("fixup! feat: add a thing") == []
    assert check("squash! feat: add a thing") == []


def test_the_comments_git_puts_in_the_file_are_not_part_of_the_message():
    raw = (
        "feat: add a thing\n"
        "# Please enter the commit message for your changes. Lines starting\n"
        "# with '#' will be ignored, and an empty message aborts the commit.\n"
        "#\n"
        "# On branch dev\n"
    )
    assert clean(raw) == "feat: add a thing"
    assert check(raw) == []


def test_the_diff_that_git_commit_v_appends_is_not_a_body():
    """Without the scissors handling, every `git commit -v` would be rejected for having a body
    — the single most likely way to make everyone start using --no-verify."""
    raw = (
        "feat: add a thing\n"
        "# ------------------------ >8 ------------------------\n"
        "# Do not modify or remove the line above.\n"
        "diff --git a/x.py b/x.py\n"
        "+Signed-off-by: not really a trailer, this is the diff\n"
    )
    assert check(raw) == []


def test_an_empty_message_is_refused_rather_than_accepted_silently():
    assert check("") == ["the message is empty"]
    assert check("# just a comment\n") == ["the message is empty"]


# --- the two ways it is invoked -------------------------------------------------------------


def test_reading_the_message_from_a_file_is_what_the_hook_does(tmp_path, capsys):
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text("feat: add a thing\n", encoding="utf-8")
    assert main([str(path)]) == 0
    path.write_text("nope\n", encoding="utf-8")
    assert main([str(path)]) == 1
    assert "type(scope): what and why" in capsys.readouterr().err


def test_a_failure_shows_an_example_that_would_have_worked(tmp_path, capsys):
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text("nope\n", encoding="utf-8")
    main([str(path)])
    err = capsys.readouterr().err
    assert "AGENTS.md §8" in err
    assert EXAMPLE in err
    assert check(EXAMPLE) == []  # the example it prints must itself pass


def test_checking_a_range_is_what_ci_does(tmp_path, capsys):
    """CI runs `--range base..head`; a repository of its own keeps the test hermetic."""
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(a, cwd=repo, check=True, capture_output=True)  # noqa: E731
    run("git", "init", "-q", "-b", "main")
    run("git", "config", "user.email", "t@example.com")
    run("git", "config", "user.name", "t")
    (repo / "a.txt").write_text("a")
    run("git", "add", "-A")
    run("git", "commit", "-q", "--no-verify", "-m", "feat: add a")
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "b.txt").write_text("b")
    run("git", "add", "-A")
    run("git", "commit", "-q", "--no-verify", "-m", "added stuff")

    import os

    cwd = os.getcwd()
    os.chdir(repo)
    try:
        assert main(["--range", f"{base}..HEAD"]) == 1  # only the second commit is bad
        assert main(["--range", f"{base}..{base}"]) == 0
    finally:
        os.chdir(cwd)
    assert "1 of 1 commit message(s) need a rewrite" in capsys.readouterr().err

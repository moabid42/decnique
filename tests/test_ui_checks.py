"""DSL typed at the prompt: block reading, defining into the session, and the check verbs."""

from __future__ import annotations

from decnique.ui.repl import block_open, dispatch, is_dsl, read_block
from decnique.ui.session import Session


def test_block_reading_ignores_braces_in_strings_and_comments():
    assert is_dsl("check c {") and is_dsl('detection d { event method = "x" }')
    assert not is_dsl("check c") and not is_dsl("check file.decn")  # the verb, not a block
    assert block_open('check c { type coverage permission "a}b" // }')
    assert not block_open("check c { type coverage }")
    lines = iter(["  type coverage", "}"])
    assert read_block("check c {", lambda: next(lines, None)).count("\n") == 2


def test_define_merges_and_replaces_by_id(tmp_path):
    s = Session()
    dispatch(s, 'detection d { event method = "A" }')
    dispatch(s, "check c { type dead_rules }")
    assert [d.id for d in s.lib.detections] == ["d"] and s.lib.bundle.checks[0].type == "dead_rules"
    dispatch(s, "check c { type redundant_rules }")  # same id → replaced, not duplicated
    assert [c.type for c in s.lib.bundle.checks] == ["redundant_rules"]
    assert dispatch(s, "check c { type nonsense }") is True  # a DSL error is reported, not raised
    dispatch(s, 'candidate k { required { iam.serviceAccountKeys.create } footprint { a: "X" } }')
    dispatch(s, "check c { type candidate for k }")
    assert [c.id for c in s.lib.bundle.candidates] == ["k"]  # candidates survive a redefine
    assert dispatch(s, "checks list") is True and dispatch(s, "ask check c") is True  # no account → cannot run

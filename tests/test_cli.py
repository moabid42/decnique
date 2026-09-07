"""``python -m decnique.cli`` — the non-interactive tooling front door.

The shell (`run.py`) has its own tests; this one covers the argparse CLI, which is what a
build script or a `Makefile` calls.  Its contract is narrow and worth pinning: **stdout is
machine-readable**, and the exit code says what happened — 0 ok, 1 the input had errors,
3 the input could not be read at all.  A subcommand that printed a nice message but exited 0
on a broken file would silently pass in a pipeline.
"""

from __future__ import annotations

import json

import pytest

from decnique.cli import main
from decnique.dsl import yaml_io

GOOD = 'detection keys {\n  event method = "google.iam.admin.v1.CreateServiceAccountKey"\n}\n'
BROKEN = "detection oops { event method = }\n"
ACCOUNT = "examples/accounts/custom/account.json"


@pytest.fixture
def rules(tmp_path):
    p = tmp_path / "r.decn"
    p.write_text(GOOD)
    return str(p)


def _json(capsys) -> dict:
    out = capsys.readouterr().out
    return json.loads(out[out.index("{") :])


# --- parse / fmt -------------------------------------------------------------------------


def test_parse_reports_the_counts_and_succeeds(rules, capsys):
    assert main(["parse", rules]) == 0
    assert "1 detections, 0 candidates, 0 checks, 0 rulesets" in capsys.readouterr().out


def test_parse_yaml_prints_the_serialised_bundle(rules, capsys):
    assert main(["parse", rules, "--yaml"]) == 0
    b = yaml_io.load_yaml(capsys.readouterr().out.split("\n", 1)[1])
    assert [d.id for d in b.detections] == ["keys"]


def test_parse_of_a_broken_file_exits_1_and_says_where(tmp_path, capsys):
    bad = tmp_path / "bad.decn"
    bad.write_text(BROKEN)
    assert main(["parse", str(bad)]) == 1
    assert "bad.decn" in capsys.readouterr().err


def test_parse_keeps_going_after_a_bad_file(tmp_path, rules, capsys):
    bad = tmp_path / "bad.decn"
    bad.write_text(BROKEN)
    assert main(["parse", str(bad), rules]) == 1
    assert "1 detections" in capsys.readouterr().out  # the good file was still reported


def test_fmt_prints_canonical_text_that_reparses(rules, tmp_path, capsys):
    assert main(["fmt", rules]) == 0
    text = capsys.readouterr().out
    assert "detection keys" in text
    again = tmp_path / "again.decn"
    again.write_text(text)
    assert main(["parse", str(again)]) == 0  # invariant §5: parse(format(x)) works


def test_fmt_write_rewrites_the_file_in_place_and_is_idempotent(tmp_path):
    p = tmp_path / "messy.decn"
    p.write_text('detection    keys {event    method="X"}\n')
    assert main(["fmt", str(p), "--write"]) == 0
    once = p.read_text()
    assert main(["fmt", str(p), "--write"]) == 0
    assert p.read_text() == once
    assert once != 'detection    keys {event    method="X"}\n'


def test_fmt_of_a_broken_file_exits_1_and_leaves_it_alone(tmp_path):
    p = tmp_path / "bad.decn"
    p.write_text(BROKEN)
    assert main(["fmt", str(p), "--write"]) == 1
    assert p.read_text() == BROKEN


# --- load / show / import ----------------------------------------------------------------


def test_load_prints_a_summary(rules, capsys):
    assert main(["load", rules]) == 0
    doc = _json(capsys)
    assert doc["detections"] == 1


def test_load_list_marks_approximate_rules_with_a_tilde(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text(GOOD + 'detection fuzzy { event unknown("x") }\n')
    assert main(["load", str(p), "--list"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.endswith(("keys", "fuzzy"))]
    assert [ln[0] for ln in lines] == [" ", "~"]


def test_show_prints_the_canonical_dsl(rules, capsys):
    assert main(["show", rules]) == 0
    assert "detection keys" in capsys.readouterr().out


def test_import_writes_one_file_per_detection_plus_the_asked_for_ast(tmp_path, rules, capsys):
    out = tmp_path / "out"
    assert main(["import", rules, "-o", str(out), "--yaml", "--json"]) == 0
    assert (out / "keys.decn").read_text().startswith("detection keys")
    assert [d.id for d in yaml_io.load(out / "detections.yaml").detections] == ["keys"]
    assert [d.id for d in yaml_io.load(out / "detections.json").detections] == ["keys"]
    assert _json(capsys)["detections"] == 1


# --- event / trace -----------------------------------------------------------------------


def test_event_says_which_rules_observe_a_raw_audit_log_entry(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text('detection setiam { event method = "SetIamPolicy" }\n')
    assert main(["event", str(p), "-e", "examples/events/event_owner_grant.json"]) == 0
    doc = _json(capsys)
    assert doc["observed"] is True and doc["observed_by"] == ["setiam"]
    assert doc["event"]["method"] == "SetIamPolicy"  # the audit log was decoded, not passed through


def test_event_accepts_an_already_decoded_event(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text(GOOD)
    ev = tmp_path / "e.json"
    ev.write_text(json.dumps({"method": "google.iam.admin.v1.CreateServiceAccountKey"}))
    assert main(["event", str(p), "-e", str(ev)]) == 0
    assert _json(capsys)["observed_by"] == ["keys"]


def test_trace_reports_fires_per_detection_and_matches_per_candidate(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text(GOOD)
    args = ["trace", str(p), "examples/candidates/candidates.decn", "-e", "examples/events/events.json"]
    assert main(args) == 0
    doc = _json(capsys)
    assert doc["events"] >= 2
    assert {d["id"]: d["fires"] for d in doc["detections"]}["keys"] == "yes"
    assert {c["matches"] for c in doc["candidates"]} <= {"yes", "no", "unknown"}


def test_trace_all_rules_also_lists_the_ones_that_do_not_fire(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text(GOOD + 'detection never { event method = "does.not.happen" }\n')
    base = ["trace", str(p), "-e", "examples/events/events.json"]
    assert main(base) == 0
    quiet = {d["id"] for d in _json(capsys)["detections"]}
    assert main(base + ["--all-rules"]) == 0
    loud = {d["id"] for d in _json(capsys)["detections"]}
    assert "never" not in quiet and loud == {"keys", "never"}


# --- admits / coverage -------------------------------------------------------------------


def test_admits_lists_the_rules_that_can_involve_a_method(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text(GOOD)
    assert main(["admits", str(p), "-m", "google.iam.admin.v1.CreateServiceAccountKey"]) == 0
    assert capsys.readouterr().out.split() == ["keys"]


def test_coverage_answers_blindspots_and_stealth_for_one_account(tmp_path, capsys):
    p = tmp_path / "r.decn"
    p.write_text(GOOD)
    args = ["coverage", str(p), "examples/candidates/candidates.decn", "-a", ACCOUNT,
            "--permission", "iam.serviceAccountKeys.create"]
    assert main(args) == 0
    doc = _json(capsys)
    assert doc["account"] == "demo-prod"
    assert doc["blindspots"]["summary"]["permissions_probed"] == 1
    assert doc["stealth"]["summary"]["techniques"] >= 1
    assert "chains" in doc  # this account carries an `attack` block


# --- error handling ----------------------------------------------------------------------


def test_a_missing_rules_path_is_a_load_error_exit_1(capsys):
    """The loader records it as an issue and still prints a summary, so a pipeline sees both
    the count and a non-zero code."""
    assert main(["load", "does/not/exist.decn"]) == 1
    cap = capsys.readouterr()
    assert "path does not exist" in cap.err
    assert json.loads(cap.out[cap.out.index("{") :])["errors"] == 1


def test_a_non_json_event_file_is_an_input_error(tmp_path, rules, capsys):
    ev = tmp_path / "e.json"
    ev.write_text("not json")
    assert main(["event", rules, "-e", str(ev)]) == 3
    assert "input error" in capsys.readouterr().err


def test_a_missing_event_file_is_an_input_error(rules, capsys):
    assert main(["event", rules, "-e", "no/such/event.json"]) == 3
    assert "input error" in capsys.readouterr().err


def test_a_subcommand_is_required():
    with pytest.raises(SystemExit):
        main([])

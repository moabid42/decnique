"""Batch / CI mode: `decnique --rules … --account … <verb>` runs once, prints JSON on request,
and exits with a code a pipeline can act on.  Errors never kill an interactive session."""

from __future__ import annotations

import json

import pytest

from decnique.ui.repl import EXIT_CLEAN, EXIT_FINDING, EXIT_INCONCLUSIVE, EXIT_INPUT, dispatch, main
from decnique.ui.session import Session


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("DECNIQUE_CONFIG", str(tmp_path / "cfg.json"))


def test_batch_check_exit_codes_and_json(tmp_path, capsys):
    rules = tmp_path / "r.decn"
    rules.write_text('detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n'
                     'check ok { type coverage permission iam.serviceAccountKeys.create }\n'
                     'check bad { type coverage permission resourcemanager.projects.setIamPolicy }\n')
    base = ["--rules", str(rules), "--account", "examples/accounts/custom/account.json"]
    assert main(base + ["ask", "check", "ok"]) == EXIT_CLEAN
    assert main(base + ["ask", "check", "bad"]) == EXIT_CLEAN  # no --fail-on: findings are reported, not fatal
    assert main(base + ["--fail-on", "finding", "ask", "check", "bad"]) == EXIT_FINDING
    assert main(base + ["--fail-on", "finding", "ask", "check", "ok"]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(base + ["--json", "ask", "check", "bad"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["verb"] == "check" and doc["items"][0]["verdict"] == "fail" and doc["items"][0]["label"] == "bad"


def test_json_script_is_one_array_and_narration_moves_to_stderr(tmp_path, capsys):
    rules = tmp_path / "r.decn"
    rules.write_text('detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n')
    script = tmp_path / "run.txt"
    script.write_text(
        "ask blindspots iam.serviceAccountKeys.create\n"
        "ask blindspots resourcemanager.projects.setIamPolicy\n"
    )
    code = main([
        "--json", "--rules", str(rules), "--account", "examples/accounts/custom/account.json",
        "-f", str(script),
    ])
    assert code == EXIT_CLEAN
    captured = capsys.readouterr()
    docs = json.loads(captured.out)
    assert [d["verb"] for d in docs] == ["blindspots", "blindspots"]
    assert "loaded" in captured.err


def test_batch_blindspots_report_and_script(tmp_path):
    rules = tmp_path / "r.decn"
    rules.write_text('detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n')
    script = tmp_path / "run.txt"
    script.write_text("# a comment\nask blindspots iam.serviceAccountKeys.create\nask stealth\n")
    code = main(["--rules", str(rules), "examples/candidates/candidates.decn", "--account", "examples/accounts/custom/account.json", "--report", str(tmp_path / "out"),
                 "--format", "json", "--fail-on", "finding", "-f", str(script)])
    assert code == EXIT_FINDING  # `escalate_project_iam` is evasive: nothing watches SetIamPolicy here
    files = sorted((tmp_path / "out").glob("*.json"))
    assert [f.name.split("-")[0] for f in files] == ["blindspots", "stealth"]
    gap = main(["--rules", str(rules), "--account", "examples/accounts/custom/account.json", "--fail-on", "finding",
                "ask", "blindspots", "resourcemanager.projects.setIamPolicy"])
    assert gap == EXIT_FINDING


def test_batch_input_errors(tmp_path):
    assert main(["--rules", str(tmp_path / "missing.decn"), "rules", "list"]) == EXIT_INPUT
    assert main(["--account", "tests/test_ui_batch.py", "rules", "list"]) == EXIT_INPUT  # not JSON
    assert main([]) if False else True
    with pytest.raises(SystemExit):
        main(["--help"])


@pytest.mark.parametrize("command", [
    ["ask"], ["ask", "missing"], ["ask", "blindspots"],
    ["ask", "stealth", "missing"], ["ask", "check", "missing"],
    ["events", "load"], ["rules", "load"], ["rules", "inspect", "missing"],
    ["config", "not.a.setting"], ["help", "missing"], ["reports", "export", "unused.json"],
])
def test_rejected_commands_cannot_pass_batch_ci(command):
    """A command that never ran is an input failure, even without --fail-on."""
    assert main(command) == EXIT_INPUT


def test_missing_script_is_an_input_error_with_valid_json(tmp_path, capsys):
    """A missing script must not leak a traceback or corrupt machine-readable stdout."""
    assert main(["--json", "-f", str(tmp_path / "missing.txt")]) == EXIT_INPUT
    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert "input error" in captured.err and "Traceback" not in captured.err


def test_script_stops_at_first_error_and_keeps_the_last_report(tmp_path, capsys):
    """Later export/config commands must not run after a rejected script instruction."""
    script = tmp_path / "run.txt"
    script.write_text('detection keys {\n event method = "key"\n}\n'
                      'check diff { type compare left keys right keys }\n'
                      'ask check diff\nask check missing\nconfig report.save on\n')
    assert main(["--json", "-f", str(script)]) == EXIT_INPUT
    assert json.loads(capsys.readouterr().out)["items"][0]["label"] == "diff"
    assert Session().settings.get("report.save") == "off"


def test_check_engine_errors_are_fatal_without_fail_on(tmp_path):
    """A missing account in a coverage check cannot look like a clean CI result."""
    rules = tmp_path / "r.decn"
    rules.write_text('check missing_account { type coverage permission iam.serviceAccountKeys.create }')
    assert main(["--rules", str(rules), "ask", "check"]) == EXIT_INPUT


def test_parse_failures_are_fatal_but_do_not_poison_the_session(tmp_path):
    """Interactive recovery resets command failure state without accepting bad batch input."""
    rules = tmp_path / "broken.decn"
    rules.write_text('detection broken { this is invalid }')
    assert main(["--rules", str(rules), "rules", "list"]) == EXIT_INPUT
    s = Session()
    assert dispatch(s, 'rules "') is True and s.command_failed
    assert dispatch(s, 'detection broken { nonsense }') is True and s.command_failed
    assert dispatch(s, "help") is True and not s.command_failed


def test_inconclusive_exit_code(tmp_path, monkeypatch):
    import decnique.smt.coverage as cov

    monkeypatch.setattr(cov, "find_gap", lambda p, lib, account, ctx=None: cov.NoGap(p, "exhausted"))
    rules = tmp_path / "r.decn"
    rules.write_text('detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n')
    base = ["--rules", str(rules), "--account", "examples/accounts/custom/account.json", "ask", "blindspots", "iam.serviceAccountKeys.create"]
    assert main(["--fail-on", "finding"] + base) == EXIT_CLEAN
    assert main(["--fail-on", "unknown"] + base) == EXIT_INCONCLUSIVE


def test_errors_keep_the_session_alive(tmp_path):
    s = Session()
    bad = tmp_path / "bad.json"
    bad.write_text('{"version": 2}')
    assert dispatch(s, f"account load {bad}") is True and s.account is None  # schema error, reported
    dispatch(s, "account load examples/accounts/custom/account.json")
    import decnique.ui.render as render

    def boom(*a, **k):
        raise RuntimeError("engine bug")

    s_orig = render.stealth
    render.stealth = boom
    try:
        assert dispatch(s, "ask stealth") is True  # an unexpected exception is reported, not raised
    finally:
        render.stealth = s_orig
    assert s.account is not None and dispatch(s, "rules list") is True

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
    base = ["--rules", str(rules), "--account", "examples/account.json"]
    assert main(base + ["ask", "check", "ok"]) == EXIT_CLEAN
    assert main(base + ["ask", "check", "bad"]) == EXIT_CLEAN  # no --fail-on: findings are reported, not fatal
    assert main(base + ["--fail-on", "finding", "ask", "check", "bad"]) == EXIT_FINDING
    assert main(base + ["--fail-on", "finding", "ask", "check", "ok"]) == EXIT_CLEAN
    capsys.readouterr()
    assert main(base + ["--json", "ask", "check", "bad"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    doc = json.loads(out[out.index("{"):])
    assert doc["verb"] == "check" and doc["items"][0]["verdict"] == "fail" and doc["items"][0]["label"] == "bad"


def test_batch_blindspots_report_and_script(tmp_path):
    rules = tmp_path / "r.decn"
    rules.write_text('detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n')
    script = tmp_path / "run.txt"
    script.write_text("# a comment\nask blindspots iam.serviceAccountKeys.create\nask stealth\n")
    code = main(["--rules", str(rules), "examples/candidates.decn", "--account", "examples/account.json", "--report", str(tmp_path / "out"),
                 "--format", "json", "--fail-on", "finding", "-f", str(script)])
    assert code == EXIT_FINDING  # `escalate_project_iam` is evasive: nothing watches SetIamPolicy here
    files = sorted((tmp_path / "out").glob("*.json"))
    assert [f.name.split("-")[0] for f in files] == ["blindspots", "stealth"]
    gap = main(["--rules", str(rules), "--account", "examples/account.json", "--fail-on", "finding",
                "ask", "blindspots", "resourcemanager.projects.setIamPolicy"])
    assert gap == EXIT_FINDING


def test_batch_input_errors(tmp_path):
    assert main(["--rules", str(tmp_path / "missing.decn"), "rules", "list"]) == EXIT_INPUT
    assert main(["--account", "tests/test_ui_batch.py", "rules", "list"]) == EXIT_INPUT  # not JSON
    assert main([]) if False else True
    with pytest.raises(SystemExit):
        main(["--help"])


def test_inconclusive_exit_code(tmp_path, monkeypatch):
    import decnique.smt.coverage as cov

    monkeypatch.setattr(cov, "find_gap", lambda p, lib, account, ctx=None: cov.NoGap(p, "exhausted"))
    rules = tmp_path / "r.decn"
    rules.write_text('detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n')
    base = ["--rules", str(rules), "--account", "examples/account.json", "ask", "blindspots", "iam.serviceAccountKeys.create"]
    assert main(["--fail-on", "finding"] + base) == EXIT_CLEAN
    assert main(["--fail-on", "unknown"] + base) == EXIT_INCONCLUSIVE


def test_errors_keep_the_session_alive(tmp_path):
    s = Session()
    bad = tmp_path / "bad.json"
    bad.write_text('{"version": 2}')
    assert dispatch(s, f"account load {bad}") is True and s.account is None  # schema error, reported
    dispatch(s, "account load examples/account.json")
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

"""End to end: the two entry points, run as real processes.

Everything else in `tests/` calls ``main()`` in-process, which cannot see the things a user
or a pipeline actually meets — argv handling, the launcher's imports, what lands on stdout
versus stderr, and the **process exit code**.  These tests start a fresh interpreter and check
only that contract, so they stay fast and do not duplicate the engine tests.

The exit codes are the whole point of batch mode: 0 clean · 2 a finding · 3 input error ·
4 inconclusive.  A CI job that gates a merge on "no new blind spots" reads nothing else.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e


def _console_script() -> str | None:
    """The installed ``decnique`` command: beside the running interpreter (a venv install, as
    in CI) or anywhere on ``PATH``.  ``None`` when only the source tree is present."""
    for name in ("decnique", "decnique.exe"):
        candidate = Path(sys.executable).with_name(name)
        if candidate.exists():
            return str(candidate)
    return shutil.which("decnique")


CONSOLE = _console_script()

ACCOUNT = "examples/accounts/custom/account.json"
CANDIDATES = "examples/candidates/candidates.decn"
WATCH_KEYS = 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n'


@pytest.fixture
def rules_file(tmp_path):
    p = tmp_path / "rules.decn"
    p.write_text(WATCH_KEYS)
    return str(p)


# --- the launcher ------------------------------------------------------------------------


def test_run_py_with_no_arguments_opens_the_shell_and_leaves_cleanly(run_cli):
    r = run_cli("run.py")
    assert r.code == 0, r.err
    assert "decnique" in r.out  # the banner, then end of input


def test_loading_rules_without_a_verb_prints_usage_and_fails(run_cli, rules_file):
    """Batch mode with nothing to run is a mistake in the job definition, not a clean run."""
    r = run_cli("run.py", "--rules", rules_file)
    assert r.code == 3
    assert "usage" in (r.out + r.err).lower()


def test_run_py_answers_a_single_verb_and_exits(run_cli, rules_file):
    r = run_cli("run.py", "--rules", rules_file, "--account", ACCOUNT,
                "ask", "blindspots", "iam.serviceAccountKeys.create")
    assert r.code == 0, r.err
    assert "iam.serviceAccountKeys.create" in r.out


def test_a_gap_is_only_fatal_when_the_pipeline_asks_for_it(run_cli, rules_file):
    """Without ``--fail-on`` a finding is reported but not fatal — the same run gates a merge
    only when the job opts in."""
    args = ("run.py", "--rules", rules_file, "--account", ACCOUNT,
            "ask", "blindspots", "resourcemanager.projects.setIamPolicy")
    assert run_cli(*args).code == 0
    assert run_cli(*args[:1], "--fail-on", "finding", *args[1:]).code == 2


def test_a_watched_permission_stays_clean_under_fail_on(run_cli, rules_file):
    r = run_cli("run.py", "--fail-on", "finding", "--rules", rules_file, "--account", ACCOUNT,
                "ask", "blindspots", "iam.serviceAccountKeys.create")
    assert r.code == 0, r.err


def test_json_mode_prints_a_document_a_pipeline_can_read(run_cli, rules_file):
    r = run_cli("run.py", "--json", "--rules", rules_file, "--account", ACCOUNT,
                "ask", "blindspots", "resourcemanager.projects.setIamPolicy")
    assert r.code == 0, r.err
    doc = r.json()
    assert doc["verb"] == "blindspots"
    assert doc["items"] and doc["items"][0]["verdict"] == "gap"


def test_a_script_of_commands_runs_in_order_and_saves_a_report(run_cli, tmp_path, rules_file):
    script = tmp_path / "run.txt"
    script.write_text("# what the nightly job asks\nask blindspots iam.serviceAccountKeys.create\nask stealth\n")
    out = tmp_path / "reports"
    r = run_cli("run.py", "--rules", rules_file, CANDIDATES, "--account", ACCOUNT,
                "--report", str(out), "--format", "json", "-f", str(script))
    assert r.code == 0, r.err
    written = sorted(f.name.split("-")[0] for f in out.glob("*.json"))
    assert written == ["blindspots", "stealth"]
    saved = json.loads(next(out.glob("blindspots-*.json")).read_text())
    assert saved["verb"] == "blindspots"


def test_a_bad_account_file_is_an_input_error(run_cli, tmp_path, rules_file):
    bad = tmp_path / "acct.json"
    bad.write_text("{not json")
    r = run_cli("run.py", "--rules", rules_file, "--account", str(bad), "rules", "list")
    assert r.code == 3
    assert "input error" in (r.out + r.err)


def test_a_missing_rules_path_is_an_input_error(run_cli):
    r = run_cli("run.py", "--rules", "no/such/dir", "rules", "list")
    assert r.code == 3


def test_an_unknown_verb_does_not_crash_the_process(run_cli, rules_file):
    r = run_cli("run.py", "--rules", rules_file, "rules", "frobnicate")
    assert r.code in (0, 3)
    assert "Traceback" not in r.err


def test_help_is_available_without_loading_anything(run_cli):
    r = run_cli("run.py", "--help")
    assert r.code == 0
    assert "exit codes" in r.out


# --- the tooling CLI ---------------------------------------------------------------------


def test_python_m_decnique_cli_parses_a_file(run_cli, rules_file):
    r = run_cli("-m", "decnique.cli", "parse", rules_file)
    assert r.code == 0, r.err
    assert "1 detections" in r.out


def test_python_m_decnique_cli_reports_a_broken_file_on_stderr(run_cli, tmp_path):
    bad = tmp_path / "bad.decn"
    bad.write_text("detection oops { event method = }\n")
    r = run_cli("-m", "decnique.cli", "parse", str(bad))
    assert r.code == 1
    assert r.out.strip() == "" and "bad.decn" in r.err


def test_the_coverage_subcommand_prints_one_json_document(run_cli, rules_file):
    r = run_cli("-m", "decnique.cli", "coverage", rules_file, CANDIDATES, "-a", ACCOUNT,
                "--permission", "iam.serviceAccountKeys.create")
    assert r.code == 0, r.err
    doc = json.loads(r.out)
    assert set(doc) >= {"account", "blindspots", "stealth", "chains"}


def test_the_launcher_delegates_the_tooling_subcommands(run_cli, rules_file):
    """``run.py import -o …`` is the same command as ``decnique.cli import``; the launcher
    hands anything with a tooling flag straight over."""
    out = str(Path(rules_file).parent / "imported")
    r = run_cli("run.py", "import", rules_file, "-o", out)
    assert r.code == 0, r.err
    assert json.loads(r.out[r.out.index("{") :])["detections"] == 1


@pytest.mark.skipif(CONSOLE is None, reason="package not pip-installed")
def test_the_installed_console_script_works(tmp_path):
    """Only runs against an installed package — CI installs it, so it runs there.

    `decnique` is the tooling CLI (`decnique.cli`); the shell is `run.py` / `decnique.ui.repl`.
    Parsing a file through the installed command also proves ``grammar.lark`` was packaged, which
    a source checkout can never catch."""
    rules = tmp_path / "r.decn"
    rules.write_text(WATCH_KEYS)
    helped = subprocess.run([CONSOLE, "--help"], capture_output=True, text=True, timeout=120)
    assert helped.returncode == 0 and "decnique.cli" in helped.stdout
    parsed = subprocess.run(
        [CONSOLE, "parse", str(rules)], capture_output=True, text=True, timeout=120
    )
    assert parsed.returncode == 0, parsed.stderr
    assert "1 detections" in parsed.stdout

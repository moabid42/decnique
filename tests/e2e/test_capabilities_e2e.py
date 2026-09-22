"""End-to-end coverage for product workflows that cross several subsystem boundaries.

These tests intentionally run the real entry points.  Unit tests already exhaustively exercise
the individual engines; this module protects the seams where loading, normalization, session
state, solver results, report serialization, and process exit codes meet.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.e2e

ACCOUNT = "examples/accounts/custom/account.json"
CANDIDATES = "examples/candidates/candidates.decn"
CHECKS = "examples/checks/checks.decn"
OWNER_EVENT = "examples/events/event_owner_grant.json"
TERRAFORM = "tests/fixtures/terraform_show.json"

TOKEN = "iam.serviceAccounts.getAccessToken"
KEY_PERMISSION = "iam.serviceAccountKeys.create"
IAM_PERMISSION = "resourcemanager.projects.setIamPolicy"
DELTA = 'udm("target.resource.attribute.labels[ser_binding_deltas_%s]")'


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_raw_owner_grant_is_normalized_and_observed_by_its_payload(run_cli, tmp_path):
    """The raw-log importer must preserve the IAM delta that the translated rule reads."""
    rules = _write(
        tmp_path / "owner.decn",
        f"""
        detection owner_grant {{
          event method = "SetIamPolicy"
            and {DELTA % "action"} = "ADD"
            and {DELTA % "role"} = "roles/owner"
            and {DELTA % "member"} startswith "user:"
        }}
        """,
    )

    result = run_cli("-m", "decnique.cli", "event", rules, "-e", OWNER_EVENT)

    assert result.code == 0, result.err
    doc = result.json()
    assert doc["observed_by"] == ["owner_grant"]
    assert doc["event"]["udm"][
        "target.resource.attribute.labels[ser_binding_deltas_role]"
    ] == "roles/owner"


def test_stealth_finds_an_evasive_principal_after_a_caught_one(run_cli, tmp_path):
    """The process result must be existential over every feasible principal, not insertion order."""
    bundle = _write(
        tmp_path / "principal.decn",
        f"""
        detection alice_only {{
          event method = "{TOKEN}" and principal = "alice@example.com"
        }}
        candidate use_token {{
          required {{ {TOKEN} }}
          footprint {{ use: "{TOKEN}" }}
        }}
        """,
    )
    account = tmp_path / "account.json"
    account.write_text(
        json.dumps(
            {
                "version": 1,
                "name": "two-actors",
                "bindings": {
                    "alice@example.com": [{"permission": TOKEN}],
                    "bob@example.com": [{"permission": TOKEN}],
                },
                "logging": {
                    "admin_activity": True,
                    "data_access_services": ["iamcredentials.googleapis.com"],
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "run.py",
        "--json",
        "--rules",
        bundle,
        "--account",
        str(account),
        "ask",
        "stealth",
        "use_token",
    )

    assert result.code == 0, result.err
    (item,) = result.json()["items"]
    assert item["verdict"] == "evasive"
    assert item["principal"] == "bob@example.com"
    assert item["schedule"][0]["principal"] == "bob@example.com"


def test_every_check_engine_runs_together_in_batch_mode(run_cli, tmp_path):
    """All documented check types must load, run, and serialize in one real process."""
    rules = _write(
        tmp_path / "rules.decn",
        """
        detection keys {
          event method = "google.iam.admin.v1.CreateServiceAccountKey"
        }
        detection keys_twin {
          event method = "google.iam.admin.v1.CreateServiceAccountKey"
        }
        check same_key_rules { type compare left keys right keys_twin }
        """,
    )

    result = run_cli(
        "run.py",
        "--json",
        "--rules",
        rules,
        CANDIDATES,
        CHECKS,
        "--account",
        ACCOUNT,
        "ask",
        "check",
    )

    assert result.code == 0, result.err
    items = result.json()["items"]
    assert {item["type"] for item in items} == {
        "coverage",
        "candidate",
        "compare",
        "dead_rules",
        "redundant_rules",
        "boundary",
        "require_coverage",
        "attempt_coverage",
        "public_access",
    }
    assert {item["verdict"] for item in items} <= {"pass", "fail", "unknown"}


def test_chains_findings_exit_two_and_export_a_replayable_plan(run_cli, tmp_path):
    """A stealthy graph path must gate CI and export every hop as raw audit-log JSON."""
    script = tmp_path / "chain.txt"
    exported = tmp_path / "chain.json"
    script.write_text(
        f"ask chains\nreports export {exported}\n",
        encoding="utf-8",
    )

    result = run_cli(
        "run.py",
        "--json",
        "--fail-on",
        "finding",
        "--rules",
        CANDIDATES,
        "--account",
        ACCOUNT,
        "-f",
        str(script),
    )

    assert result.code == 2, result.err
    doc = result.json()
    assert doc["summary"]["found"] is True and doc["summary"]["hops"] == 2
    events = json.loads(exported.read_text(encoding="utf-8"))
    assert {event["protoPayload"]["methodName"] for event in events} == {
        "google.iam.admin.v1.CreateServiceAccountKey",
        TOKEN,
    }
    assert all(event["_decnique"]["verdict"] == "stealthy" for event in events)


def test_terraform_account_import_reaches_the_shell_and_solver(run_cli, tmp_path):
    """A Terraform plan must become scoped grants before a subprocess asks coverage questions."""
    listed = run_cli(
        "run.py",
        "--account",
        TERRAFORM,
        "account",
        "who",
        KEY_PERMISSION,
    )
    assert listed.code == 0, listed.err
    assert "converted from Terraform" in listed.out
    assert "sec@demo.com" in listed.out

    rules = _write(
        tmp_path / "keys.decn",
        'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n',
    )
    covered = run_cli(
        "run.py",
        "--json",
        "--rules",
        rules,
        "--account",
        TERRAFORM,
        "ask",
        "blindspots",
        KEY_PERMISSION,
    )
    assert covered.code == 0, covered.err
    assert covered.json()["items"][0]["verdict"] == "all_covered"


def test_suggest_define_closes_a_gap_in_the_same_session(run_cli, tmp_path):
    """Generated DSL must merge into session state and change the next solver result."""
    rules = _write(
        tmp_path / "unrelated.decn",
        'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n',
    )
    script = tmp_path / "suggest.txt"
    script.write_text(
        f"ask blindspots {IAM_PERMISSION}\n"
        f"ask suggest {IAM_PERMISSION} define\n"
        f"ask blindspots {IAM_PERMISSION}\n",
        encoding="utf-8",
    )

    result = run_cli(
        "run.py",
        "--json",
        "--rules",
        rules,
        "--account",
        ACCOUNT,
        "-f",
        str(script),
    )

    assert result.code == 0, result.err
    before, after = result.json()
    assert before["items"][0]["verdict"] == "gap"
    assert after["items"][0]["verdict"] == "all_covered"


def test_fail_on_unknown_uses_the_documented_exit_four(run_cli, tmp_path):
    """An unsupported proof mode must never become either a clean pass or a finding."""
    bundle = _write(
        tmp_path / "unknown.decn",
        f"""
        detection policy {{ event method = "SetIamPolicy" }}
        check background {{
          type boundary
          permission {IAM_PERMISSION}
          event granted = true
          mode fires_bg
        }}
        """,
    )

    result = run_cli(
        "run.py",
        "--json",
        "--fail-on",
        "unknown",
        "--rules",
        bundle,
        "--account",
        ACCOUNT,
        "ask",
        "check",
    )

    assert result.code == 4, result.err
    assert result.json()["items"][0]["verdict"] == "unknown"

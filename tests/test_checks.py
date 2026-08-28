"""The DSL's `check` blocks run and answer three-valued, with replayed witnesses."""

from __future__ import annotations

import pytest

from decnique.checks import CheckError, run_check, run_checks
from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires

_D = 'udm("target.resource.attribute.labels[ser_binding_deltas_%s]")'
_SET = "resourcemanager.projects.setIamPolicy"
_KEY = "iam.serviceAccountKeys.create"
_SRC = f"""
detection owner_added {{
  event method = "SetIamPolicy" and {_D % "action"} = "ADD" and {_D % "role"} = "roles/owner"
}}
detection owner_added_twin {{
  event method = "SetIamPolicy" and {_D % "role"} = "roles/owner" and {_D % "action"} = "ADD"
}}
detection any_policy_change {{
  event method = "SetIamPolicy"
}}
detection watch_keys {{
  event method = "google.iam.admin.v1.CreateServiceAccountKey"
}}
candidate make_key {{
  required {{ {_KEY} }}
  footprint {{ act: "google.iam.admin.v1.CreateServiceAccountKey" }}
}}
"""


def _lib(extra: str = "") -> DetectionLibrary:
    return DetectionLibrary(parse_text(_SRC + extra, "t.decn"))


def _account(*perms: str) -> Account:
    return Account(
        name="t",
        bindings={"a@x.com": tuple(Grant(permission=p) for p in perms)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset()),
    )


def _check(src: str):
    return parse_text(src, "c.decn").checks[0]


# --- coverage ----------------------------------------------------------------------------------


def test_coverage_pass_and_fail_with_replayed_witness():
    lib, acct = _lib(), _account(_SET, _KEY)
    ok = run_check(_check(f'check keys {{ type coverage permission {_KEY} }}'), lib, acct)
    assert ok.verdict == "pass" and "watch_keys" in ok.rows[0].note
    # only two of the three SetIamPolicy rules are used; a role *removal* dodges both owner rules
    bad = run_check(
        _check(f'check iam {{ type coverage permission {_SET} rules [owner_added, owner_added_twin] }}'),
        lib, acct,
    )
    assert bad.verdict == "fail"
    ev = bad.rows[0].witness
    assert all(fires(d.spec, [ev]) is not True for d in lib.detections if d.id != "any_policy_change")


def test_coverage_event_option_narrows_the_question():
    lib, acct = _lib(), _account(_SET)
    src = f'check owner {{ type coverage permission {_SET} rules [owner_added] event {_D % "action"} = "ADD" and {_D % "role"} = "roles/owner" }}'
    assert run_check(_check(src), lib, acct).verdict == "pass"


def test_coverage_glob_and_vacuous_permissions():
    lib, acct = _lib(), _account(_KEY)
    r = run_check(_check('check g { type coverage permissions like "iam.serviceAccount*" }'), lib, acct)
    labels = {row.label: row for row in r.rows}
    assert labels[_KEY].verdict == "pass"
    assert any("vacuous" in row.note for row in r.rows)  # unreachable permissions pass vacuously


# --- candidate ---------------------------------------------------------------------------------


def test_candidate_check_verdicts():
    lib = _lib()
    caught = run_check(_check("check c { type candidate for make_key }"), lib, _account(_KEY))
    assert caught.verdict in ("pass", "unknown")  # a proof or an honest exhaustion — never "fail"
    evasive = run_check(_check("check c { type candidate for make_key rules [owner_added] }"), lib, _account(_KEY))
    assert evasive.verdict == "fail" and evasive.rows[0].witness
    vac = run_check(_check("check c { type candidate for make_key }"), lib, _account(_SET))
    assert vac.verdict == "pass" and "vacuous" in vac.detail
    with pytest.raises(CheckError):
        run_check(_check("check c { type candidate for nope }"), lib, _account(_KEY))


# --- compare / dead / redundant ---------------------------------------------------------------


def test_compare_equivalent_and_different():
    lib = _lib()
    same = run_check(_check("check s { type compare left owner_added right owner_added_twin }"), lib)
    assert same.verdict == "pass"
    diff = run_check(_check("check d { type compare left owner_added right any_policy_change }"), lib)
    assert diff.verdict == "fail"
    assert [r.verdict for r in diff.rows] == ["pass", "fail"]  # the broad rule sees more


def test_dead_and_redundant_rules():
    lib, acct = _lib(), _account(_SET)
    dead = run_check(_check("check d { type dead_rules }"), lib, acct)
    assert dead.verdict == "fail"
    assert {r.label for r in dead.rows if r.verdict == "fail"} == {"watch_keys"}  # nobody holds the key permission
    live = [r for r in dead.rows if r.verdict == "pass"]
    assert live and all(fires(lib.get(r.label).spec, [r.witness]) is True for r in live)
    red = run_check(_check("check r { type redundant_rules rules [owner_added, any_policy_change] }"), lib, acct)
    by = {r.label: r.verdict for r in red.rows}
    assert by == {"owner_added": "fail", "any_policy_change": "pass"}


# --- honesty + batch ---------------------------------------------------------------------------


def test_unimplemented_type_is_unknown_and_batch_runs():
    lib, acct = _lib(), _account(_SET)
    checks = parse_text(
        f"check a {{ type boundary }}\ncheck b {{ type coverage permission {_SET} }}", "c.decn"
    ).checks
    res = run_checks(checks, lib, acct)
    assert [r.verdict for r in res] == ["unknown", "pass"]
    with pytest.raises(CheckError):
        run_check(checks[1], lib, None)  # coverage needs Reach / Log

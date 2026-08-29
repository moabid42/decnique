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
        f'check a {{ type boundary event granted = true mode fires_bg }}\ncheck b {{ type coverage permission {_SET} }}', "c.decn"
    ).checks
    res = run_checks(checks, lib, acct)
    assert [r.verdict for r in res] == ["unknown", "pass"]
    with pytest.raises(CheckError):
        run_check(checks[1], lib, None)  # coverage needs Reach / Log


# --- boundary / require_coverage / attempt_coverage / public_access ----------------------------

_DENY = f'''
detection denied_calls {{ event method = "SetIamPolicy" and granted = false }}
detection owner_granted {{ event method = "SetIamPolicy" and {_D % "role"} = "roles/owner" and granted = true }}
detection corr_only {{
  events {{ e: method = "google.iam.admin.v1.CreateServiceAccountKey" }}
  window 1h
  condition #e >= 3
}}
'''


def test_boundary_allowed_and_modes():
    lib, acct = _lib(_DENY), _account(_SET, _KEY)
    # every owner grant must be seen: holds (owner_added fires on all of them)
    src = f'check b {{ type boundary event {_D % "action"} = "ADD" and {_D % "role"} = "roles/owner" }}'
    assert run_check(_check(src), lib, acct).verdict == "pass"
    # with only the owner rules, "every ADD must be seen" fails (adding roles/viewer slips) …
    add = f'check b {{ type boundary permission {_SET} event {_D % "action"} = "ADD" rules [owner_added, owner_added_twin] %s }}'
    r = run_check(_check(add % ""), lib, acct)
    assert r.verdict == "fail" and r.rows[0].witness["udm"]["target.resource.attribute.labels[ser_binding_deltas_action]"] == "ADD"
    # … unless non-owner roles (and deltas that carry no role at all) are explicitly allowed to slip
    assert run_check(_check(add % f'allowed {_D % "role"} != "roles/owner" or {_D % "role"} missing'), lib, acct).verdict == "pass"
    # key creation is only watched by a correlation rule: `fires_single` slips, `observed` holds
    keys = 'check k { type boundary permission %s rules [corr_only] event method = "google.iam.admin.v1.CreateServiceAccountKey" %s }'
    assert run_check(_check(keys % (_KEY, "")), lib, acct).verdict == "fail"
    assert run_check(_check(keys % (_KEY, "mode observed")), lib, acct).verdict == "pass"
    assert run_check(_check(keys % (_KEY, "mode fires_bg")), lib, acct).verdict == "unknown"
    with pytest.raises(CheckError):
        run_check(_check("check b { type boundary }"), lib, acct)


def test_require_and_attempt_coverage():
    lib, acct = _lib(_DENY), _account(_SET, _KEY)
    src = _SRC + _DENY + f'''
candidate own {{
  required {{ {_SET} }}
  footprint {{ grant: "SetIamPolicy" where {_D % "action"} = "ADD" and {_D % "role"} = "roles/owner" }}
}}'''
    lib = DetectionLibrary(parse_text(src, "t.decn"))
    assert run_check(_check("check r { type require_coverage for own step grant }"), lib, acct).verdict == "pass"
    # the successful grant is watched, and so is a denied attempt (by denied_calls) …
    assert run_check(_check("check a { type attempt_coverage for own }"), lib, acct).verdict == "pass"
    # … but a rule that insists on granted = true misses the denied attempt while catching the success
    r = run_check(_check("check a { type attempt_coverage for own rules [owner_granted] }"), lib, acct)
    assert r.verdict == "fail" and r.rows[0].witness["granted"] is False
    assert run_check(_check("check r { type require_coverage for own rules [owner_granted] }"), lib, acct).verdict == "pass"
    with pytest.raises(CheckError):
        run_check(_check("check r { type require_coverage for own step nope }"), lib, acct)


def test_public_access():
    lib = _lib()
    private = run_check(_check("check p { type public_access }"), lib, _account(_KEY))
    assert private.verdict == "pass" and "vacuous" in private.detail
    acct = Account(
        name="t",
        bindings={"allUsers": (Grant(permission=_SET, resource="projects/demo"),),
                  "a@x.com": (Grant(permission=_KEY),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset()),
    )
    r = run_check(_check("check p { type public_access rules [owner_added] }"), lib, acct)
    assert [x.label for x in r.rows] == [f"{_SET} as allUsers on projects/demo"]  # only anonymous grants are asked
    assert r.verdict == "fail" and r.rows[0].witness["principal"] == "allUsers"
    assert r.rows[0].witness["resource"] == "projects/demo"
    assert run_check(_check('check p { type public_access resource like "projects/demo*" rules [any_policy_change] }'), lib, acct).verdict == "pass"
    assert run_check(_check('check p { type public_access resource like "projects/other*" }'), lib, acct).verdict == "pass"

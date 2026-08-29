"""M3 acceptance: symbolic stealth is sound (differential replay) and the canonical timing
case resolves both directions."""

from __future__ import annotations

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires, matches_footprint
from decnique.smt.stealth import AlwaysDetected, Evasive, NotFeasible, feasible, stealth_feasible

_TOKEN = "iam.serviceAccounts.getAccessToken"


def _lib(src: str) -> DetectionLibrary:
    return DetectionLibrary(parse_text(src, "t.decn"))


def _candidate(src: str):
    return parse_text(src, "t.decn").candidates[0]


def _account(*perms: str) -> Account:
    return Account(
        name="t",
        bindings={"attacker@x.com": tuple(Grant(permission=p) for p in perms)},
        # data-access logging on for the token service: these tests are about timing, and an
        # unlogged step is (correctly) invisible to every rule
        logging=LogConfig(admin_activity=True, data_access_services=frozenset({"iamcredentials.googleapis.com"})),
    )


# --- feasibility -------------------------------------------------------------------------


def test_feasible_requires_all_permissions():
    c = _candidate(
        """
        candidate esc {
          required { iam.serviceAccounts.getAccessToken iam.serviceAccountKeys.create }
          footprint { use: "iam.serviceAccounts.getAccessToken" }
        }
        """
    )
    assert feasible(c, _account(_TOKEN)) == ()  # missing the second permission
    both = _account(_TOKEN, "iam.serviceAccountKeys.create")
    assert feasible(c, both) == ("attacker@x.com",)


def test_not_feasible_result():
    c = _candidate(
        """
        candidate esc {
          required { iam.serviceAccountKeys.create }
          footprint { use: "iam.serviceAccounts.getAccessToken" }
        }
        """
    )
    r = stealth_feasible(c, _lib("detection d { event method = \"x\" }"), _account(_TOKEN))
    assert isinstance(r, NotFeasible)


# --- the canonical timing case: SAT (spread to evade) ------------------------------------


def _rate_candidate(repeat: int, span: str | None) -> str:
    span_line = f"span {span}" if span else ""
    return f"""
        candidate burst_use {{
          required {{ iam.serviceAccounts.getAccessToken }}
          footprint {{
            use: "{_TOKEN}" repeat {repeat}
            {span_line}
          }}
        }}
    """


def test_canonical_evasion_sat_by_spreading():
    # rule fires at >10 within a 10-minute window; technique needs 12 uses but span is wide →
    # the solver must spread them so no 10-minute window holds >10.
    lib = _lib(
        f'detection rate {{ events {{ e: method = "{_TOKEN}" }}'
        f" window 600s condition #e > 10 }}"
    )
    c = _candidate(_rate_candidate(12, "6h"))
    r = stealth_feasible(c, lib, _account(_TOKEN))
    assert isinstance(r, Evasive), r
    # differential replay: footprint realized, and NO rule fires on the schedule
    assert matches_footprint(c.footprint, list(r.schedule)) is True
    for d in lib.detections:
        assert fires(d.spec, list(r.schedule)) is not True


def test_canonical_always_detected_when_span_forbids_spreading():
    # same rule, but the technique must complete within 5 minutes (< the 10-minute window) →
    # every 10-minute window holds all 12 events → always detected → UNSAT.
    lib = _lib(
        f'detection rate {{ events {{ e: method = "{_TOKEN}" }}'
        f" window 600s condition #e > 10 }}"
    )
    c = _candidate(_rate_candidate(12, "300s"))
    r = stealth_feasible(c, lib, _account(_TOKEN))
    assert isinstance(r, AlwaysDetected), r


# --- differential replay on a distinct-IP rule -------------------------------------------


def test_evasion_respects_distinct_and_replays_clean():
    # rule fires when >=2 distinct IPs are seen; technique uses distinct IPs by construction but
    # only 1 use → below threshold → evadable, and must replay clean.
    lib = _lib(
        f"""
        detection multi_ip {{ events {{ e: method = "{_TOKEN}" }}
          aggregates {{ ips = count_distinct(e.caller_ip) }}
          condition ips >= 3 }}
        """
    )
    c = _candidate(
        f"""
        candidate esc {{
          required {{ iam.serviceAccounts.getAccessToken }}
          footprint {{ use: "{_TOKEN}" repeat 2 distinct caller_ip span 1h }}
        }}
        """
    )
    r = stealth_feasible(c, lib, _account(_TOKEN))
    assert isinstance(r, Evasive), r
    assert matches_footprint(c.footprint, list(r.schedule)) is True
    for d in lib.detections:
        assert fires(d.spec, list(r.schedule)) is not True


# --- honesty: an Unknown-based rule makes stealth approximate -----------------------------


def test_stealth_with_unknown_rule_is_approximate():
    lib = _lib(
        f"""
        detection approx {{ event method = "{_TOKEN}" and unknown("panther:python_logic") }}
        """
    )
    c = _candidate(
        f"""
        candidate esc {{
          required {{ iam.serviceAccounts.getAccessToken }}
          footprint {{ use: "{_TOKEN}" repeat 2 span 1h }}
        }}
        """
    )
    r = stealth_feasible(c, lib, _account(_TOKEN))
    assert isinstance(r, Evasive)
    assert r.approximate is True
    assert "approx" in r.unknown_rules


# --- payload: a footprint step's `where` is what the attacker actually does ----------------

_DELTA = 'udm("target.resource.attribute.labels[ser_binding_deltas_%s]")'
_OWNER_TO_SA = f"""
    detection owner_to_sa {{
      event method = "SetIamPolicy"
        and {_DELTA % "action"} = "ADD"
        and {_DELTA % "role"} = "roles/owner"
        and {_DELTA % "member"} startswith "serviceAccount:"
    }}
"""


def _escalate(member_clause: str) -> str:
    return f"""
    candidate esc {{
      required {{ resourcemanager.projects.setIamPolicy }}
      footprint {{
        act: "SetIamPolicy"
          where {_DELTA % "action"} = "ADD" and {_DELTA % "role"} = "roles/owner"
            and {member_clause}
        span 1h
      }}
    }}
    """


def test_payload_human_owner_is_evasive_and_schedule_carries_payload():
    lib = _lib(_OWNER_TO_SA + _escalate(f'{_DELTA % "member"} startswith "user:"'))
    c = lib.bundle.candidates[0]
    r = stealth_feasible(c, lib, _account("resourcemanager.projects.setIamPolicy"))
    assert isinstance(r, Evasive) and not r.approximate
    ev = r.schedule[0]
    labels = ev["udm"]
    assert labels["target.resource.attribute.labels[ser_binding_deltas_action]"] == "ADD"
    assert labels["target.resource.attribute.labels[ser_binding_deltas_role]"] == "roles/owner"
    assert labels["target.resource.attribute.labels[ser_binding_deltas_member]"].startswith("user:")
    assert ev["event_type"] == "USER_RESOURCE_UPDATE_PERMISSIONS"


def test_payload_service_account_owner_is_always_detected():
    lib = _lib(_OWNER_TO_SA + _escalate(f'{_DELTA % "member"} startswith "serviceAccount:"'))
    c = lib.bundle.candidates[0]
    r = stealth_feasible(c, lib, _account("resourcemanager.projects.setIamPolicy"))
    assert isinstance(r, AlwaysDetected)


# --- honesty: proofs only when the engine really proved something ----------------------------


def test_vacuous_rule_does_not_make_everything_always_detected():
    # `#e < 5` holds on the empty trace: the rule observes nothing and must not count.
    lib = _lib('detection v { events { e: method = "x" } window 1h condition #e < 5 }')
    c = _candidate(f'candidate t {{ required {{ {_TOKEN} }} footprint {{ use: "{_TOKEN}" }} }}')
    acct = Account(name="t", bindings={"a@x.com": (Grant(permission=_TOKEN),)},
                   logging=LogConfig(data_access_services=frozenset({"iamcredentials.googleapis.com"})))
    r = stealth_feasible(c, lib, acct)
    assert isinstance(r, Evasive) and not r.unlogged


def test_unlogged_step_is_invisible_to_rules_and_reported():
    lib = _lib(f'detection d {{ event method = "{_TOKEN}" }}')
    c = _candidate(f'candidate t {{ required {{ {_TOKEN} }} footprint {{ use: "{_TOKEN}" }} }}')
    logged = Account(name="t", bindings={"a@x.com": (Grant(permission=_TOKEN),)},
                     logging=LogConfig(data_access_services=frozenset({"iamcredentials.googleapis.com"})))
    assert isinstance(stealth_feasible(c, lib, logged), AlwaysDetected)
    off = Account(name="t", bindings={"a@x.com": (Grant(permission=_TOKEN),)},
                  logging=LogConfig(data_access_services=frozenset()))  # never written
    r = stealth_feasible(c, lib, off)
    assert isinstance(r, Evasive) and r.unlogged == (_TOKEN,)


def test_unknown_footprint_payload_is_exhausted_not_proof():
    from decnique.smt.stealth import Exhausted

    lib = _lib('detection d { event method = "x" }')
    c = _candidate(f'candidate t {{ required {{ {_TOKEN} }} footprint {{ use: "{_TOKEN}" where unknown("t") }} }}')
    acct = Account(name="t", bindings={"a@x.com": (Grant(permission=_TOKEN),)},
                   logging=LogConfig(data_access_services=frozenset({"iamcredentials.googleapis.com"})))
    r = stealth_feasible(c, lib, acct)
    assert isinstance(r, Exhausted)

"""M3 acceptance: symbolic stealth is sound (differential replay) and the canonical timing
case resolves both directions."""

from __future__ import annotations

import pytest

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Deny, Grant, LogConfig
from decnique.eval import fires, matches_footprint
from decnique.eval.candidate import matches_candidate
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


def test_stealth_searches_every_feasible_principal():
    """A principal-specific rule must not hide another feasible actor's evasion."""
    c = _candidate(
        f'candidate esc {{ required {{ {_TOKEN} }} footprint {{ use: "{_TOKEN}" }} }}'
    )
    lib = _lib(
        f'detection alice_only {{ event method = "{_TOKEN}" '
        'and principal = "alice@x.com" }'
    )
    account = Account(
        name="t",
        bindings={
            "alice@x.com": (Grant(permission=_TOKEN),),
            "bob@x.com": (Grant(permission=_TOKEN),),
        },
        logging=LogConfig(
            data_access_services=frozenset({"iamcredentials.googleapis.com"})
        ),
    )

    r = stealth_feasible(c, lib, account)

    assert isinstance(r, Evasive), r
    assert r.principal == "bob@x.com"
    assert r.schedule[0]["principal"] == "bob@x.com"


def test_always_detected_covers_every_feasible_principal():
    """An always-detected proof must include the whole feasible actor domain."""
    c = _candidate(
        f'candidate esc {{ required {{ {_TOKEN} }} footprint {{ use: "{_TOKEN}" }} }}'
    )
    lib = _lib(
        f'detection alice {{ event method = "{_TOKEN}" and principal = "alice@x.com" }}\n'
        f'detection bob {{ event method = "{_TOKEN}" and principal = "bob@x.com" }}'
    )
    account = Account(
        name="t",
        bindings={
            "alice@x.com": (Grant(permission=_TOKEN),),
            "bob@x.com": (Grant(permission=_TOKEN),),
        },
        logging=LogConfig(
            data_access_services=frozenset({"iamcredentials.googleapis.com"})
        ),
    )

    r = stealth_feasible(c, lib, account)

    assert isinstance(r, AlwaysDetected), r
    assert set(r.caught_by) == {"alice", "bob"}


def test_unshared_principal_cannot_be_invented_to_evade():
    """Overriding share may vary actors across events, but every actor must remain feasible."""
    c = _candidate(
        f"""
        candidate esc {{
          required {{ {_TOKEN} }}
          footprint {{ use: "{_TOKEN}" }}
          share caller_ip
        }}
        """
    )
    lib = _lib(
        f'detection alice {{ event method = "{_TOKEN}" and principal = "alice@x.com" }}'
    )
    account = Account(
        name="t",
        bindings={"alice@x.com": (Grant(permission=_TOKEN),)},
        logging=LogConfig(
            data_access_services=frozenset({"iamcredentials.googleapis.com"})
        ),
    )

    assert isinstance(stealth_feasible(c, lib, account), AlwaysDetected)


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


@pytest.mark.parametrize(("actor", "required", "payload", "context"), [
    ('actor principal = "nobody@example.com"', _TOKEN, "", ""),
    ("", _TOKEN, "", "context false"),
    ("", f'{_TOKEN} on resource = "projects/forbidden"', "", ""),
    ("", _TOKEN, 'where resource = "projects/forbidden"', ""),
    ("", _TOKEN, "where false", ""),
])
def test_impossible_candidate_is_not_reported_as_evasion_or_detection(actor, required, payload, context):
    """Ignoring an actor, context or target scope must never invent an exact attack schedule."""
    candidate = _candidate(f'''
candidate scoped {{
  {actor}
  required {{ {required} }}
  footprint {{ use: "{_TOKEN}" {payload} }}
  {context}
}}
''')
    account = _account(_TOKEN)
    account.bindings = {"attacker@x.com": (Grant(_TOKEN, "projects/allowed"),)}
    assert isinstance(stealth_feasible(candidate, _lib(""), account), NotFeasible)


def test_scoped_candidate_replays_on_a_granted_descendant():
    """Project grants must allow real descendants while retaining all candidate predicates."""
    resource = "//example.googleapis.com/projects/p/resources/child"
    candidate = _candidate(f'''
candidate scoped {{
  actor principal_type = "USER"
  required {{ {_TOKEN} on resource = "{resource}" }}
  footprint {{ use: "{_TOKEN}" }}
  context tags.environment = "prod"
}}
''')
    account = _account(_TOKEN)
    account.bindings = {"attacker@x.com": (Grant(_TOKEN, "projects/p"),)}
    account.hierarchy = {resource: "projects/p"}
    result = stealth_feasible(candidate, _lib(""), account)
    assert isinstance(result, Evasive), result
    assert matches_candidate(candidate, result.schedule, account) is True
    assert result.schedule[0]["resource"] == resource
    assert result.schedule[0]["tags"]["environment"] == "prod"
    forged = [{**result.schedule[0], "resource": "projects/forbidden"}]
    assert matches_candidate(candidate, forged, account) is False


def test_scoped_deny_prevents_a_candidate_on_the_denied_resource():
    """Possessing a permission elsewhere must not bypass a deny on the attack's target."""
    candidate = _candidate(f'''candidate denied {{
      required {{ {_TOKEN} }}
      footprint {{ use: "{_TOKEN}" where resource = "projects/denied" }}
    }}''')
    account = _account(_TOKEN)
    account.deny = (Deny("attacker@x.com", _TOKEN, "projects/denied"),)
    assert isinstance(stealth_feasible(candidate, _lib(""), account), NotFeasible)


def test_actor_type_cannot_be_fabricated_for_a_service_account():
    """A service account cannot satisfy a human-only technique by changing its event type."""
    candidate = _candidate(f'''candidate human {{
      actor principal_type = "USER"
      required {{ {_TOKEN} }}
      footprint {{ use: "{_TOKEN}" }}
    }}''')
    account = _account(_TOKEN)
    account.bindings = {"robot@p.iam.gserviceaccount.com": (Grant(_TOKEN),)}
    assert isinstance(stealth_feasible(candidate, _lib(""), account), NotFeasible)


def test_unknown_context_remains_inconclusive():
    """An unsupported candidate guard cannot certify evasion or always-detected coverage."""
    from decnique.smt.stealth import Exhausted

    candidate = _candidate(f'''candidate unknown_context {{
      required {{ {_TOKEN} }}
      footprint {{ use: "{_TOKEN}" }}
      context unknown("environment")
    }}''')
    assert isinstance(stealth_feasible(candidate, _lib(""), _account(_TOKEN)), Exhausted)


def test_each_step_uses_its_own_permission_scope():
    """A technique using two services need not hold both permissions on both resources."""
    key = "iam.serviceAccountKeys.create"
    candidate = _candidate(f'''candidate two_targets {{
      required {{ {key} on resource = "projects/keys" {_TOKEN} on resource = "projects/tokens" }}
      footprint {{
        key: "google.iam.admin.v1.CreateServiceAccountKey"
        token: "{_TOKEN}"
      }}
    }}''')
    account = _account(key, _TOKEN)
    account.bindings = {"attacker@x.com": (Grant(key, "projects/keys"), Grant(_TOKEN, "projects/tokens"))}
    result = stealth_feasible(candidate, _lib(""), account)
    assert isinstance(result, Evasive), result
    assert [e["resource"] for e in result.schedule] == ["projects/keys", "projects/tokens"]
    assert matches_candidate(candidate, result.schedule, account) is True

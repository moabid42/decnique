"""M4 acceptance: stealthy-chain recovery, no-path proof, hop-by-hop validation."""

from __future__ import annotations

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires, matches_footprint
from decnique.graph.search import NoStealthyPath, StealthyPath, search_stealth_path
from decnique.graph.state import Technique, account_for

_KEY = "google.iam.admin.v1.CreateServiceAccountKey"
_TOKEN = "iam.serviceAccounts.getAccessToken"
_SETIAM = "google.cloud.resourcemanager.v3.Projects.SetIamPolicy"

_CANDIDATES = f"""
candidate create_key {{
  required {{ iam.serviceAccountKeys.create }}
  footprint {{ act: "{_KEY}" span 1h }}
}}
candidate mint_token {{
  required {{ iam.serviceAccounts.getAccessToken }}
  footprint {{ act: "{_TOKEN}" span 1h }}
}}
candidate escalate {{
  required {{ resourcemanager.projects.setIamPolicy }}
  footprint {{ act: "{_SETIAM}" span 1h }}
}}
"""


def _techniques() -> list[Technique]:
    bundle = parse_text(_CANDIDATES, "c.decn")
    by_id = {c.id: c for c in bundle.candidates}
    # declared effect table: each hop grows Reach
    return [
        Technique(by_id["create_key"], gains=("iam.serviceAccounts.getAccessToken",)),
        Technique(by_id["mint_token"], gains=("resourcemanager.projects.setIamPolicy",)),
        Technique(by_id["escalate"], gains=("resourcemanager.projects.getIamPolicy",)),
    ]


def _base_account() -> Account:
    # attacker starts with only key-creation; other permissions are earned along the chain
    return Account(
        name="t",
        bindings={"attacker@x.com": (Grant(permission="iam.serviceAccountKeys.create"),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset([
            "iamcredentials.googleapis.com",
        ])),
    )


def _lib(src: str = "") -> DetectionLibrary:
    return DetectionLibrary(parse_text(src or "detection noop { event method = \"none\" }", "r.decn"))


# --- known-chain recovery ----------------------------------------------------------------


def test_known_chain_recovered_as_stealthy_when_rules_miss():
    techniques = _techniques()
    lib = _lib()  # a rule that matches nothing in the chain
    start = frozenset({"iam.serviceAccountKeys.create"})
    r = search_stealth_path(
        techniques, lib, _base_account(), "attacker@x.com", start,
        goal="resourcemanager.projects.setIamPolicy",
    )
    assert isinstance(r, StealthyPath), r
    assert [h.technique for h in r.hops] == ["create_key", "mint_token"]


def test_path_is_valid_hop_by_hop():
    techniques = _techniques()
    lib = _lib()
    start = frozenset({"iam.serviceAccountKeys.create"})
    r = search_stealth_path(
        techniques, lib, _base_account(), "attacker@x.com", start,
        goal="resourcemanager.projects.setIamPolicy",
    )
    assert isinstance(r, StealthyPath)
    by_id = {t.id: t for t in techniques}
    state = start
    for hop in r.hops:
        tech = by_id[hop.technique]
        # Required ⊆ current state
        assert all(p in state for p in tech.required), (hop.technique, state)
        # effect applied to produce the next state
        assert hop.to_state == tech.apply(state)
        # the hop's stealth witness replays clean through M0
        assert matches_footprint(tech.candidate.footprint, list(hop.schedule)) is True
        for d in lib.detections:
            assert fires(d.spec, list(hop.schedule)) is not True
        state = hop.to_state
    assert "resourcemanager.projects.setIamPolicy" in state


# --- no-path proof -----------------------------------------------------------------------


def test_no_stealthy_path_when_a_rule_fires_on_every_route():
    techniques = _techniques()
    # single-event rules that fire on the two methods needed to progress → every route trips
    lib = _lib(
        f"""
        detection watch_key {{ event method = "{_KEY}" }}
        detection watch_token {{ event method = "{_TOKEN}" }}
        """
    )
    start = frozenset({"iam.serviceAccountKeys.create"})
    r = search_stealth_path(
        techniques, lib, _base_account(), "attacker@x.com", start,
        goal="resourcemanager.projects.setIamPolicy",
    )
    assert isinstance(r, NoStealthyPath), r
    assert r.reason == "exhausted"  # a real proof, not a truncated bound
    assert r.states_explored >= 1


def test_partial_detection_still_allows_alternate_stealthy_hop():
    # only the KEY method is watched; but mint_token needs getAccessToken which the attacker
    # cannot get without create_key → since create_key trips, the goal is unreachable stealthily
    techniques = _techniques()
    lib = _lib(f'detection watch_key {{ event method = "{_KEY}" }}')
    start = frozenset({"iam.serviceAccountKeys.create"})
    r = search_stealth_path(
        techniques, lib, _base_account(), "attacker@x.com", start,
        goal="resourcemanager.projects.setIamPolicy",
    )
    assert isinstance(r, NoStealthyPath)


# --- account growth ----------------------------------------------------------------------


def test_account_for_grants_state_permissions():
    base = _base_account()
    state = frozenset({"a.b.c", "d.e.f"})
    acct = account_for(base, "attacker@x.com", state)
    assert acct.reach("attacker@x.com", "a.b.c")
    assert acct.reach("attacker@x.com", "d.e.f")
    assert not acct.reach("attacker@x.com", "x.y.z")


# --- the whole path is replayed, not only each hop ------------------------------------------


def _join_lib(extra: str = "") -> DetectionLibrary:
    # "a key is created, then a token minted by the same principal within an hour"
    return DetectionLibrary(parse_text(f'''
detection key_then_token {{
  events {{
    k: method = "{_KEY}"
    t: method = "{_TOKEN}"
  }}
  join {{ k.principal = t.principal }}
  window 1h
  condition #k >= 1 and #t >= 1
}}
{extra}
''', "j.decn"))


def _account() -> Account:
    return Account(name="t", bindings={"a@x.com": (Grant(permission="iam.serviceAccountKeys.create"),)},
                   logging=LogConfig(data_access_services=frozenset({"iamcredentials.googleapis.com"})))


def test_path_waits_out_a_correlation_window():
    res = search_stealth_path(_techniques(), _join_lib(), _account(), "a@x.com",
                              frozenset({"iam.serviceAccountKeys.create"}), "resourcemanager.projects.setIamPolicy")
    assert isinstance(res, StealthyPath) and [h.technique for h in res.hops] == ["create_key", "mint_token"]
    assert res.hops[0].delay == 0 and res.hops[1].delay == 3601  # a patient attacker waits out the window
    # the whole path, laid end to end with that delay, fires nothing
    whole = list(res.hops[0].schedule) + [{**e, "time": e["time"] + 3601 + max(x["time"] for x in res.hops[0].schedule)}
                                          for e in res.hops[1].schedule]
    assert fires(_join_lib().detections[0].spec, whole) is False
    assert not res.approximate


def test_path_is_refused_when_no_delay_evades_the_correlation():
    # the same join rule without a window: the two hops correlate however long the attacker waits
    lib = DetectionLibrary(parse_text(f'''
detection key_then_token_ever {{
  events {{ k: method = "{_KEY}"  t: method = "{_TOKEN}" }}
  join {{ k.principal = t.principal }}
  condition #k >= 1 and #t >= 1
}}''', "j.decn"))
    res = search_stealth_path(_techniques(), lib, _account(), "a@x.com",
                              frozenset({"iam.serviceAccountKeys.create"}), "resourcemanager.projects.setIamPolicy")
    assert isinstance(res, NoStealthyPath)

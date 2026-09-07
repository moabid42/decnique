"""A technique's holes as regions (plan §6, §7.2, §9.1).

`ask stealth` proves a blind spot by producing one schedule.  One schedule tells a defender
almost nothing about how much room the attacker has: is that the single timing that slips
through, or does every run over ten minutes slip through?  These tests pin down the wider
answer, and — most importantly — check it against the engine that already answers the narrow
one, because the two must never disagree about whether a technique can evade at all.
"""

from __future__ import annotations

import pytest

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires, matches_footprint
from decnique.regions.domains import Numeric
from decnique.regions.technique import (
    FULLY_COVERED,
    PARTLY,
    UNDETERMINED,
    region_report,
)
from decnique.smt.stealth import AlwaysDetected, Evasive, stealth_feasible

TOKEN = "iam.serviceAccounts.getAccessToken"
BACKENDS = ("interval", "smt")


def _lib(src: str) -> DetectionLibrary:
    return DetectionLibrary(parse_text(src, "t.decn"))


def _account(*perms: str) -> Account:
    return Account(
        name="t",
        bindings={"attacker@x.com": tuple(Grant(permission=p) for p in perms or (TOKEN,))},
        logging=LogConfig(
            admin_activity=True,
            data_access_services=frozenset({"iamcredentials.googleapis.com"}),
        ),
    )


RATE = f'detection rate {{ events {{ e: method = "{TOKEN}" }} window 600s condition #e > 10 }}'


def _burst(repeat: int, span: str) -> str:
    return f'candidate burst {{ required {{ {TOKEN} }} footprint {{ use: "{TOKEN}" repeat {repeat} span {span} }} }}'


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_hole_is_a_range_of_spans_not_one_schedule(backend):
    """The point of the whole feature.  A rule counting more than ten uses in ten minutes is
    evaded by *every* run spread past the window — the defender needs the boundary, 600 s, not
    a single example timestamped somewhere beyond it."""
    lib = _lib(RATE + _burst(12, "6h"))
    r = region_report(lib.bundle.candidates[0], lib, _account(), backend=backend)
    assert r.status == PARTLY
    assert len(r.holes) == 1
    hole = r.holes[0]
    assert hole.box.get("span") == Numeric(lo=601, hi=21600, na=False)
    assert hole.box.get("count") == Numeric.exactly(12)
    assert r.crossed[0].rule == "rate"
    assert r.crossed[0].escape_axes == ("span",)  # the one knob that leaves the rule


@pytest.mark.parametrize("backend", BACKENDS)
def test_every_reported_hole_carries_a_run_that_really_evades(backend):
    """Invariant #2 for regions: the witness is rebuilt as events and replayed, so a region is
    never reported on the strength of the encoding alone."""
    lib = _lib(RATE + _burst(12, "6h"))
    c = lib.bundle.candidates[0]
    r = region_report(c, lib, _account(), backend=backend)
    for hole in r.holes:
        assert hole.replayed is True
        assert matches_footprint(c.footprint, list(hole.schedule)) is True
        for d in lib.detections:
            assert fires(d.spec, list(hole.schedule)) is not True


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_technique_that_cannot_be_spread_has_no_region_at_all(backend):
    """The other direction: when the technique must finish inside the rule's window, there is
    no evading run, and the report must say fully covered rather than shrug."""
    lib = _lib(RATE + _burst(12, "300s"))
    r = region_report(lib.bundle.candidates[0], lib, _account(), backend=backend)
    assert r.status == FULLY_COVERED
    assert r.holes == ()


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("span", ["6h", "300s"])
def test_the_region_agrees_with_the_stealth_engine(backend, span):
    """Two independent engines, one question: can this technique evade?  `stealth_feasible`
    searches for a schedule, the region view subtracts boxes.  If they ever disagree, one of
    them is lying about a blind spot."""
    lib = _lib(RATE + _burst(12, span))
    c = lib.bundle.candidates[0]
    verdict = stealth_feasible(c, lib, _account())
    r = region_report(c, lib, _account(), backend=backend)
    if isinstance(verdict, Evasive):
        assert r.holes, "stealth found an evading schedule but the region view found no hole"
        assert any(h.box.contains_point({
            "count": len(verdict.schedule),
            "span": max(e["time"] for e in verdict.schedule)
                    - min(e["time"] for e in verdict.schedule),
            "method": verdict.schedule[0]["method"],
        }) for h in r.holes), "the schedule stealth returned lies outside every reported region"
    elif isinstance(verdict, AlwaysDetected):
        assert r.status == FULLY_COVERED


# --- the honesty rules ------------------------------------------------------------------------


def test_a_rule_outside_the_encoded_class_is_listed_not_approximated():
    """Plan §5.4.  A rule the view cannot read exactly is dropped, which can only invent a hole
    — and the report has to say so, or the analyst reads a caveat-free blind spot that isn't one."""
    lib = _lib(
        f'detection joined {{ events {{ a: method = "{TOKEN}" b: method = "x" }} '
        f"join {{ a.principal = b.principal }} condition #a >= 1 }}" + _burst(12, "6h")
    )
    r = region_report(lib.bundle.candidates[0], lib, _account())
    assert [rid for rid, _ in r.excluded_rules] == ["joined"]
    assert "join" in r.excluded_rules[0][1]
    assert r.approximate is True


def test_an_unlogged_method_is_a_logging_gap_not_a_rule_gap():
    """If the account never writes the method to the audit log, no rule can see the technique.
    Saying 'no rule covers this' without saying why would point the analyst at the rules."""
    off = Account(name="t", bindings={"a@x.com": (Grant(permission=TOKEN),)},
                  logging=LogConfig(data_access_services=frozenset()))
    lib = _lib(RATE + _burst(12, "6h"))
    r = region_report(lib.bundle.candidates[0], lib, off)
    assert r.excluded_rules[0][0] == "(all rules)"
    assert "audit log" in r.excluded_rules[0][1]


def test_a_footprint_this_view_cannot_model_says_so_instead_of_guessing():
    """Several steps need one axis set per step — a different space.  Answering anyway would
    mean reporting a region for a technique that was never modelled."""
    two = _lib(
        RATE + f'candidate multi {{ required {{ {TOKEN} }} footprint {{ '
        f'a: "{TOKEN}"  b: "SetIamPolicy"  order a < b  span 1h }} }}'
    )
    r = region_report(two.bundle.candidates[0], two, _account())
    assert r.status == UNDETERMINED
    assert "several steps" in r.caveats[0]

    distinct = _lib(
        RATE + f'candidate d {{ required {{ {TOKEN} }} footprint {{ '
        f'use: "{TOKEN}" repeat 3 distinct caller_ip span 1h }} }}'
    )
    r2 = region_report(distinct.bundle.candidates[0], distinct, _account())
    assert r2.status == UNDETERMINED
    assert "caller_ip" in r2.caveats[0]


def test_an_untranslatable_payload_widens_the_technique_and_says_so():
    """Candidates may be over-approximated, rules may not (plan §2.4).  A payload the compiler
    cannot read makes the reported region *wider* than the truth, with a caveat — never narrower,
    which would drop runs the attacker can actually perform."""
    lib = _lib(
        RATE + f'candidate u {{ required {{ {TOKEN} }} footprint {{ '
        f'use: "{TOKEN}" repeat 12 where unknown("panther:python") span 6h }} }}'
    )
    r = region_report(lib.bundle.candidates[0], lib, _account())
    assert any("more runs than the technique really performs" in c for c in r.caveats)
    assert r.approximate is True


def test_the_report_serialises_for_the_json_answer():
    """The batch/CI path reads this dictionary; a hole that cannot be serialised is a hole the
    pipeline never sees."""
    lib = _lib(RATE + _burst(12, "6h"))
    summary = region_report(lib.bundle.candidates[0], lib, _account()).summary()
    assert summary["status"] == PARTLY
    assert summary["axes"][:2] == ["count", "span"]
    assert "span ∈ [601, 21600]s" in summary["holes"][0]["variables"]
    assert summary["holes"][0]["replayed"] is True
    assert summary["crossed_rules"][0]["escape_axes"] == ["span"]


# --- the count axis ----------------------------------------------------------------------------


def test_every_count_condition_is_read_as_the_right_range():
    """`#e > 10` and `#e >= 10` differ by exactly one run, and that one run is the difference
    between a technique being caught and not.  Read directly, because a bare `#e < n` is true on
    an empty trace and so never reaches this code through a live rule."""
    from decnique.model.trace import Count, CTrue
    from decnique.regions.technique import _count_region

    assert _count_region(CTrue()) == Numeric.at_least(1)
    assert _count_region(Count(var="e", op=">", n=10)) == Numeric.at_least(11)
    assert _count_region(Count(var="e", op=">=", n=10)) == Numeric.at_least(10)
    assert _count_region(Count(var="e", op="<", n=10)) == Numeric.at_most(9)
    assert _count_region(Count(var="e", op="<=", n=10)) == Numeric.at_most(10)
    assert _count_region(Count(var="e", op="=", n=10)) == Numeric.exactly(10)


@pytest.mark.parametrize(
    ("condition", "span_hole"),
    [("#e >= 12", Numeric(lo=601, hi=21600, na=False)),
     ("#e = 12", Numeric(lo=601, hi=21600, na=False))],
)
def test_a_threshold_the_technique_meets_leaves_only_the_timing(condition, span_hole):
    lib = _lib(
        f'detection rate {{ events {{ e: method = "{TOKEN}" }} window 600s condition {condition} }}'
        + _burst(12, "6h")
    )
    r = region_report(lib.bundle.candidates[0], lib, _account())
    assert r.holes[0].box.get("span") == span_hole


def test_a_threshold_the_technique_never_reaches_leaves_the_whole_run_open():
    """Twelve uses can never trip a rule that needs thirteen, so no timing helps the defender —
    the region is the technique itself, not a slice of it."""
    lib = _lib(
        f'detection rate {{ events {{ e: method = "{TOKEN}" }} window 600s condition #e > 12 }}'
        + _burst(12, "6h")
    )
    r = region_report(lib.bundle.candidates[0], lib, _account())
    assert r.holes[0].box.get("span") == Numeric(lo=0, hi=21600, na=False)
    assert r.crossed == ()  # the rule cannot fire on this technique at all


def test_a_rule_that_fires_on_an_empty_trace_observes_nothing():
    """`#e < 5` holds before the attacker does anything, so counting it as coverage would make
    every technique look watched."""
    lib = _lib(
        f'detection vacuous {{ events {{ e: method = "{TOKEN}" }} window 1h condition #e < 5 }}'
        + _burst(12, "6h")
    )
    r = region_report(lib.bundle.candidates[0], lib, _account())
    assert r.excluded_rules == (("vacuous", "fires on an empty trace, so it observes nothing"),)
    assert r.holes[0].box.get("span") == Numeric(lo=0, hi=21600, na=False)


def test_a_condition_outside_a_plain_count_is_excluded():
    lib = _lib(
        f'detection agg {{ events {{ e: method = "{TOKEN}" }} '
        "aggregates { ips = count_distinct(e.caller_ip) } condition ips >= 3 }" + _burst(12, "6h")
    )
    r = region_report(lib.bundle.candidates[0], lib, _account())
    assert [rid for rid, _ in r.excluded_rules] == ["agg"]


# --- the payload -------------------------------------------------------------------------------

_DELTA = 'udm("target.resource.attribute.labels[ser_binding_deltas_%s]")'


def test_a_udm_payload_lands_where_the_oracle_reads_it():
    """`udm:` values live under `event["udm"]`.  A witness that puts them anywhere else replays
    clean for the wrong reason — no rule matches because the fields are not where rules look."""
    perm = "resourcemanager.projects.setIamPolicy"
    lib = _lib(
        f'detection owner {{ event method = "SetIamPolicy" and {_DELTA % "role"} = "roles/editor" }}'
        f'candidate esc {{ required {{ {perm} }} footprint {{ act: "SetIamPolicy" '
        f'where {_DELTA % "action"} = "ADD" and {_DELTA % "role"} = "roles/owner" span 1h }} }}'
    )
    acct = Account(name="t", bindings={"a@x.com": (Grant(permission=perm),)},
                   logging=LogConfig(admin_activity=True))
    r = region_report(lib.bundle.candidates[0], lib, acct)
    assert r.holes, r.caveats
    event = r.holes[0].schedule[0]
    labels = event["udm"]
    assert labels["target.resource.attribute.labels[ser_binding_deltas_action]"] == "ADD"
    assert labels["target.resource.attribute.labels[ser_binding_deltas_role]"] == "roles/owner"
    assert r.holes[0].replayed is True

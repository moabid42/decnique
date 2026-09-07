"""``answers.py`` — the engine's JSON, as a build script sees it.

The interactive verbs narrate the same engine; this module is the machine-readable form the
`coverage` subcommand prints.  Two things have to hold for it to be usable in a pipeline:
the shape is stable (a consumer can index into it), and **every verdict carries its own
``exact`` / ``approximate`` tag** — an approximate finding that arrives looking exact is the
one failure mode this project exists to avoid (invariant #1).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decnique.answers import (
    blindspots_report,
    chains_report,
    full_report,
    stealth_report,
    techniques_for,
)
from decnique.detections import DetectionLibrary
from decnique.env import load_account

ACCOUNT = "examples/accounts/custom/account.json"
CANDIDATES = "examples/candidates/candidates.decn"
KEY_PERM = "iam.serviceAccountKeys.create"
IAM_PERM = "resourcemanager.projects.setIamPolicy"
WATCH_KEYS = 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }\n'


@pytest.fixture
def account():
    return load_account(ACCOUNT)


@pytest.fixture
def lib(tmp_path):
    """One rule, watching service-account key creation, plus the example techniques."""
    rules = tmp_path / "r.decn"
    rules.write_text(WATCH_KEYS)
    return DetectionLibrary.load(str(rules), CANDIDATES)


@pytest.fixture
def unwatched_lib():
    """The same techniques with nothing watching them at all."""
    return DetectionLibrary.load(CANDIDATES)


@pytest.fixture
def attack():
    return json.loads(Path(ACCOUNT).read_text(encoding="utf-8"))["attack"]


# --- blindspots --------------------------------------------------------------------------


def test_a_watched_permission_is_reported_as_covered(lib, account):
    rep = blindspots_report(lib, account, (KEY_PERM,))
    assert rep["gaps"] == []
    assert KEY_PERM in rep["covered"]
    assert rep["summary"]["permissions_probed"] == 1


def test_an_unwatched_permission_is_reported_as_a_gap_with_a_concrete_event(lib, account):
    rep = blindspots_report(lib, account, (IAM_PERM,))
    (gap,) = rep["gaps"]
    assert gap["permission"] == IAM_PERM
    assert gap["tag"] in ("exact", "approximate")
    assert gap["event"]["method"], "a gap must come with an event that shows it"


def test_every_permission_lands_in_exactly_one_bucket(lib, account):
    rep = blindspots_report(lib, account, (KEY_PERM, IAM_PERM, "storage.objects.get"))
    buckets = (
        [g["permission"] for g in rep["gaps"]]
        + rep["covered"]
        + rep["unreachable"]
        + rep["unlogged"]
    )
    assert len(buckets) == len(set(buckets)) == rep["summary"]["permissions_probed"]


def test_an_approximate_rule_makes_the_verdict_say_so(tmp_path, account):
    rules = tmp_path / "r.decn"
    rules.write_text('detection fuzzy { event method = "SetIamPolicy" and unknown("re.capture") }\n')
    rep = blindspots_report(DetectionLibrary.load(str(rules)), account, (IAM_PERM,))
    tagged = [g["tag"] for g in rep["gaps"]] + ["covered"] * len(rep["covered"])
    assert "exact" not in tagged, "a rule we could not fully translate cannot yield an exact gap"


# --- stealth -----------------------------------------------------------------------------


def test_stealth_reports_one_verdict_per_candidate(lib, account):
    rep = stealth_report(lib, account)
    assert rep["summary"]["techniques"] == len(lib.bundle.candidates)
    assert {t["candidate"] for t in rep["techniques"]} == {c.id for c in lib.bundle.candidates}


def test_an_evasive_technique_comes_with_the_schedule_that_evades(lib, account):
    rep = stealth_report(lib, account)
    evasive = [t for t in rep["techniques"] if t["verdict"] == "evasive"]
    assert evasive, "nothing here watches SetIamPolicy, so escalation must be evasive"
    for t in evasive:
        assert t["events"] == len(t["schedule"]) >= 1
        assert t["tag"] in ("exact", "approximate")
        assert t["principal"]


def test_a_non_evasive_verdict_carries_no_schedule(lib, account):
    """The keys of an entry follow its verdict: only ``evasive`` has a witness to show."""
    for t in stealth_report(lib, account)["techniques"]:
        if t["verdict"] != "evasive":
            assert "schedule" not in t and "tag" not in t


# --- chains ------------------------------------------------------------------------------


def test_only_candidates_that_gain_something_can_advance_a_chain(lib, account):
    named = {t.candidate.id for t in techniques_for(lib, account)}
    assert named == {c.id for c in lib.bundle.candidates if c.gains}


def test_an_effects_override_replaces_a_candidates_own_gains(lib, account):
    override = {c.id: ["made.up.permission"] for c in lib.bundle.candidates}
    gains = {t.candidate.id: t.gains for t in techniques_for(lib, account, override)}
    assert set(gains) == {c.id for c in lib.bundle.candidates}  # even the ones that gained nothing
    assert all(g == ("made.up.permission",) for g in gains.values())


def test_chains_finds_the_escalation_path_the_example_account_describes(unwatched_lib, account, attack):
    rep = chains_report(unwatched_lib, account, attack)
    assert rep["goal"] == IAM_PERM
    assert rep["found"] is True
    assert [h["technique"] for h in rep["hops"]] == ["create_service_account_key", "mint_access_token"]
    assert rep["tag"] in ("exact", "approximate")
    for hop in rep["hops"]:
        assert hop["gains"] and hop["events"] == len(hop["schedule"])


def test_one_rule_on_the_first_hop_closes_the_whole_chain(lib, account, attack):
    """The point of the tool: the path above only exists while every hop is stealthy.  Watching
    key creation breaks the first hop, and the search then has nothing to build on."""
    rep = chains_report(lib, account, attack)
    assert rep["found"] is False
    assert rep["reason"]


def test_an_unreachable_goal_says_why_instead_of_pretending(unwatched_lib, account):
    rep = chains_report(unwatched_lib, account, {"goal": "no.such.permission", "max_depth": 2})
    assert rep["found"] is False
    assert rep["reason"] and rep["states_explored"] >= 0


def test_the_default_attacker_is_the_most_capable_principal(unwatched_lib, account):
    """With no ``principal`` or ``initial_state`` given, the search starts from whoever holds
    the most — the strongest attacker the account admits, not an arbitrary one."""
    rep = chains_report(unwatched_lib, account, {"goal": IAM_PERM})
    assert rep["goal"] == IAM_PERM
    assert rep["found"] is True  # admin@demo.com already holds it


# --- the bundle --------------------------------------------------------------------------


def test_full_report_bundles_the_three_answers_and_the_counts(lib, account):
    rep = full_report(lib, account, permissions=(KEY_PERM,))
    assert rep["account"] == "demo-prod"
    assert rep["detections_loaded"] == len(lib.detections)
    assert rep["candidates_loaded"] == len(lib.bundle.candidates)
    assert set(rep) == {"account", "detections_loaded", "candidates_loaded", "blindspots", "stealth"}


def test_chains_are_only_included_when_an_attack_is_given(lib, account):
    rep = full_report(lib, account, permissions=(KEY_PERM,), attack={"goal": IAM_PERM})
    assert "chains" in rep


def test_the_report_is_json_serialisable(lib, account):
    """It is printed with ``json.dumps``; a stray tuple or frozenset would only show up here."""
    rep = full_report(lib, account, permissions=(KEY_PERM, IAM_PERM), attack={"goal": IAM_PERM})
    assert json.loads(json.dumps(rep)) == rep

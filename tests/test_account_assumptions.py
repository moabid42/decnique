"""Unresolved account imports must remain visible in every downstream confidence claim."""

from __future__ import annotations

from decnique.answers import blindspots_report, chains_report, stealth_report
from decnique.checks import run_check
from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env import account_from_dict, normalize_account_doc
from decnique.graph.state import account_for
from decnique.smt.coverage import Gap, find_gap

KEY = "iam.serviceAccountKeys.create"
METHOD = "google.iam.admin.v1.CreateServiceAccountKey"


def _account():
    return account_from_dict(normalize_account_doc({
        "bindings": [{
            "role": "roles/iam.serviceAccountKeyAdmin",
            "members": ["user:alice@example.com"],
            "condition": {"title": "never", "expression": "false"},
        }],
    }, resource="projects/demo"))


def _lib(watched=False):
    predicate = f'method = "{METHOD}"' if watched else "false"
    return DetectionLibrary(parse_text(f'''
detection keys {{ event {predicate} }}
candidate key {{ required {{ {KEY} }} footprint {{ act: "{METHOD}" }} }}
check coverage {{ type coverage permission {KEY} }}
check candidate_caught {{ type candidate for key }}
check compare {{ type compare left keys right keys }}
'''))


def test_conditional_grant_cannot_produce_an_exact_gap():
    """A load-time IAM warning must not disappear when a witness is exported as exact."""
    account = _account()
    assert account.assumptions and "conditional binding" in account.assumptions[0]
    result = find_gap(KEY, _lib(), account)
    assert isinstance(result, Gap)
    assert result.approximate and result.caveats == account.assumptions
    report = blindspots_report(_lib(), account, (KEY,))
    assert report["gaps"][0]["tag"] == "approximate"
    assert report["gaps"][0]["caveats"] == list(account.assumptions)


def test_assumed_account_cannot_be_counted_as_covered():
    """Inconclusive permissions must not enter the covered bucket of machine reports."""
    report = blindspots_report(_lib(True), _account(), (KEY,))
    assert report["covered"] == []
    assert report["exhausted"] == [KEY]
    assert report["summary"]["permissions_probed"] == 1
    assert report["summary"]["covered"] == 0
    assert report["caveats"]


def test_stealth_preserves_import_assumptions_for_findings_and_proofs():
    """An imported assumption must qualify evasion and prevent an unqualified detection proof."""
    account = _account()
    evasive = stealth_report(_lib(), account)["techniques"][0]
    assert evasive["tag"] == "approximate" and evasive["caveats"]
    caught = stealth_report(_lib(True), account)["techniques"][0]
    assert caught["verdict"] == "exhausted" and caught["caveats"]


def test_account_checks_keep_caveats_but_rule_comparison_is_independent():
    """A saved check cannot pass through uncertain Reach/Log; pure rule comparison still can."""
    lib, account = _lib(True), _account()
    for check in lib.bundle.checks[:2]:
        result = run_check(check, lib, account)
        assert result.verdict == "unknown" and result.approximate and result.caveats
        assert not any(row.verdict == "pass" for row in result.rows)
    assert run_check(lib.bundle.checks[2], lib, account).verdict == "pass"


def test_chain_state_and_already_held_goals_keep_account_assumptions():
    """Rebuilding chain state or finding a zero-hop path must not erase import uncertainty."""
    account = _account()
    assert account_for(account, "alice@example.com", frozenset({KEY})).assumptions == account.assumptions
    result = chains_report(_lib(), account, {"principal": "alice@example.com", "goal": KEY})
    assert result["found"] and result["tag"] == "approximate" and result["caveats"]


def test_unknown_role_is_an_account_assumption():
    """Missing role expansions must not certify that their permissions are unreachable."""
    account = account_from_dict({"bindings": {"alice@example.com": [{"role": "roles/unknownRole"}]}})
    assert account.assumptions
    result = find_gap(KEY, _lib(), account)
    assert result.reason == "exhausted" and result.caveats

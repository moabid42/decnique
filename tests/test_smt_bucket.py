"""M5 acceptance: bucketed coverage equals unbucketed, with fewer solver calls."""

from __future__ import annotations

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.smt.bucket import bucketed_gaps, coverage_signature
from decnique.smt.coverage import Gap, find_gap


def _lib() -> DetectionLibrary:
    return DetectionLibrary(
        parse_text(
            """
            detection watch_key { event method = "google.iam.admin.v1.CreateServiceAccountKey" }
            detection watch_token {
              event method = "iam.serviceAccounts.getAccessToken"
                and not caller_ip in cidr ["10.0.0.0/8"]
            }
            """,
            "r.decn",
        )
    )


def _account() -> Account:
    perms = (
        "iam.serviceAccountKeys.create",
        "iam.serviceAccounts.getAccessToken",
        "resourcemanager.projects.setIamPolicy",
        "storage.objects.get",
    )
    return Account(
        name="t",
        bindings={"attacker@x.com": tuple(Grant(permission=p) for p in perms)},
        logging=LogConfig(
            admin_activity=True,
            data_access_services=frozenset(
                ["iamcredentials.googleapis.com", "storage.googleapis.com"]
            ),
        ),
    )


def test_bucketed_equals_unbucketed():
    lib, acct = _lib(), _account()
    perms = (
        "iam.serviceAccountKeys.create",
        "iam.serviceAccounts.getAccessToken",
        "resourcemanager.projects.setIamPolicy",
        "storage.objects.get",
    )
    results, stats = bucketed_gaps(lib, acct, perms)
    for p in perms:
        direct = find_gap(p, lib, acct)
        got = results[p]
        assert type(got) is type(direct), p
        if isinstance(direct, Gap):
            assert isinstance(got, Gap)
            assert got.event == direct.event, p
            assert got.approximate == direct.approximate, p
        else:
            assert got.reason == direct.reason, p
    assert stats.permissions == len(perms)


def test_bucketing_reduces_solver_calls_when_signatures_collide():
    lib, acct = _lib(), _account()
    # two permissions with the same signature (both unreachable → identical solve)
    perms = ("unreachable.one", "unreachable.two", "iam.serviceAccountKeys.create")
    assert coverage_signature("unreachable.one", acct) == coverage_signature("unreachable.two", acct)
    _, stats = bucketed_gaps(lib, acct, perms)
    assert stats.signatures < stats.permissions
    assert stats.solver_calls_saved >= 1

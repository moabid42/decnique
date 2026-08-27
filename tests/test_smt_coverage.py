"""M2 acceptance: symbolic single-event coverage is sound and small-domain complete."""

from __future__ import annotations

import itertools

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires
from decnique.smt.coverage import Gap, NoGap, find_gap


def _lib(src: str) -> DetectionLibrary:
    return DetectionLibrary(parse_text(src, "t.decn"))


def _account(perm: str, method_logged: bool = True) -> Account:
    return Account(
        name="t",
        bindings={"attacker@x.com": (Grant(permission=perm, resource="*"),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset()),
    )


# --- soundness: every witness replays clean -----------------------------------------------


def test_gap_witness_is_unobserved_reachable_logged():
    # one rule watches getAccessToken from outside 10/8; the permission is setIamPolicy which
    # no rule covers → a gap must exist and must replay as unobserved.
    lib = _lib(
        """
        detection watch_token {
          event method = "iam.serviceAccounts.getAccessToken"
            and not caller_ip in cidr ["10.0.0.0/8"]
        }
        """
    )
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, Gap)
    # replay: no rule fires on the witness (the soundness contract)
    assert all(fires(d.spec, [r.event]) is not True for d in lib.detections)
    assert acct.logged(r.event["method"])
    assert acct.reach(r.event["principal"], r.permission, r.event.get("resource", "*"))


def test_covered_permission_returns_no_gap():
    # the only logged method for the permission is watched by a rule with no extra constraint
    lib = _lib(
        """
        detection watch_key {
          event method = "google.iam.admin.v1.CreateServiceAccountKey"
        }
        """
    )
    acct = _account("iam.serviceAccountKeys.create")
    r = find_gap("iam.serviceAccountKeys.create", lib, acct)
    assert isinstance(r, NoGap)
    assert r.reason == "all_covered"


def test_realism_invariants_stop_fabricated_witnesses():
    # A rule that fires only on a *realistic* key-creation event: product_name and granted are
    # fixed by the method / by authorization.  Without the method→field invariants the solver
    # could dodge it with an empty product_name (a false blind spot); with them the rule always
    # fires, so the permission is covered.
    lib = _lib(
        """
        detection watch_key {
          event method = "google.iam.admin.v1.CreateServiceAccountKey"
            and product_name = "Google Cloud IAM" and granted = true
        }
        """
    )
    acct = _account("iam.serviceAccountKeys.create")
    r = find_gap("iam.serviceAccountKeys.create", lib, acct)
    assert isinstance(r, NoGap) and r.reason == "all_covered"


def test_witness_is_a_complete_realistic_event():
    # a permission no rule covers still yields a gap, and its witness carries the fields a real
    # audit event fixes by its method (service, product_name) plus an authorized granted.
    lib = _lib("""detection d { event method = "storage.objects.get" }""")
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, Gap)
    assert r.event.get("granted") is True
    assert r.event.get("service") == "cloudresourcemanager.googleapis.com"
    assert r.event.get("product_name") == "Google Cloud Platform"


def test_unreachable_permission():
    lib = _lib("""detection d { event method = "storage.objects.get" }""")
    acct = _account("iam.serviceAccountKeys.create")  # grants a different permission
    r = find_gap("storage.objects.get", lib, acct)
    assert isinstance(r, NoGap) and r.reason == "unreachable"


def test_unlogged_permission_is_no_logged_method():
    # data-access service not enabled → getAccessToken not logged → no CoverageGap (needs Log)
    lib = _lib("""detection d { event method = "storage.objects.get" }""")
    acct = Account(
        name="t",
        bindings={"a@x.com": (Grant(permission="iam.serviceAccounts.getAccessToken"),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset()),
    )
    r = find_gap("iam.serviceAccounts.getAccessToken", lib, acct)
    assert isinstance(r, NoGap) and r.reason == "no_logged_method"


# --- honesty ------------------------------------------------------------------------------


def test_unknown_only_coverage_is_approximate():
    # the sole rule "covers" the method only via an Unknown atom → gap must be approximate
    lib = _lib(
        """
        detection approx_watch {
          event method = "google.iam.admin.v1.CreateServiceAccountKey"
            and unknown("panther:python_logic")
        }
        """
    )
    acct = _account("iam.serviceAccountKeys.create")
    r = find_gap("iam.serviceAccountKeys.create", lib, acct)
    assert isinstance(r, Gap)
    assert r.approximate is True
    assert "approx_watch" in r.unknown_rules


# --- small-domain completeness: solver vs brute force -------------------------------------


def _brute_force_gap_exists(lib: DetectionLibrary, acct: Account, permission: str) -> bool:
    """Enumerate a tiny finite event domain; does an unobserved reachable+logged event exist?"""
    cat = acct.catalog
    logged = [m for m in cat.methods_for(permission) if acct.logged(m)]
    principals = list(acct.principals_with(permission))
    ips = ["10.1.2.3", "203.0.113.5", "192.168.0.9"]
    resources = ["projects/p", "*"]
    for method, principal, ip, res in itertools.product(logged, principals, ips, resources):
        ev = {"method": method, "principal": principal, "caller_ip": ip, "resource": res}
        if not acct.reach(principal, permission, res):
            continue
        if all(fires(d.spec, [ev]) is not True for d in lib.detections):
            return True
    return False


def test_small_domain_completeness_sat():
    lib = _lib(
        """
        detection watch_token {
          event method = "iam.serviceAccounts.getAccessToken"
            and caller_ip in cidr ["10.0.0.0/8"]
        }
        """
    )
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, Gap)
    assert _brute_force_gap_exists(lib, acct, "resourcemanager.projects.setIamPolicy")


def test_small_domain_completeness_unsat():
    # every logged method for the permission is watched unconditionally → no gap either way
    lib = _lib(
        """
        detection a { event method = "google.iam.admin.v1.SetIAMPolicy" }
        detection b { event method = "google.cloud.resourcemanager.v3.Projects.SetIamPolicy" }
        detection c { event method = "SetIamPolicy" }
        """
    )
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, NoGap)
    assert not _brute_force_gap_exists(lib, acct, "resourcemanager.projects.setIamPolicy")

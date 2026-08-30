"""M2 acceptance: symbolic single-event coverage is sound and small-domain complete."""

from __future__ import annotations

import itertools

from decnique.detections import DetectionLibrary
from decnique.dsl.parser import parse_text
from decnique.env.catalog import Catalog
from decnique.env.model import Account, Grant, LogConfig
from decnique.eval import fires
from decnique.smt.coverage import CoverageContext, Gap, NoGap, find_gap


def _lib(src: str) -> DetectionLibrary:
    return DetectionLibrary(parse_text(src, "t.decn"))


def _account(perm: str, method_logged: bool = True) -> Account:
    return Account(
        name="t",
        bindings={"attacker@x.com": (Grant(permission=perm, resource="*"),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset()),
        catalog=Catalog.seed(),  # these tests reason about the hand-checked seed entries
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


def test_fires_on_one_event_folds_only_single_event_triggers():
    # a #v>=1 correlation rule fires on one event → foldable into the coverage formula; a #v>=2
    # (or multi-variable) rule needs several events, so it must NOT be folded (would be unsound).
    from dataclasses import dataclass

    from decnique.model.trace import Count, CTrue
    from decnique.smt.coverage import _count_true, _fires_on_one_event

    @dataclass
    class E:
        name: str

    @dataclass
    class S:
        events: list
        condition: object

    assert _fires_on_one_event(S([E("e")], Count(var="e", op=">=", n=1))) is True
    assert _fires_on_one_event(S([E("e")], CTrue())) is True
    assert _fires_on_one_event(S([E("e")], Count(var="e", op=">=", n=2))) is False
    assert _fires_on_one_event(S([E("e"), E("f")], Count(var="e", op=">=", n=1))) is False
    assert _count_true(">=", 1, 1) and not _count_true(">=", 1, 2)


# --- realism: a policy-change witness carries its change list -------------------------------


def test_setiampolicy_witness_carries_event_type_and_binding_deltas():
    # No rule covers the permission, but the witness must still look like a real audit event:
    # event_type pinned by the method, and the binding-delta labels present with values.
    lib = _lib("""detection d { event method = "storage.objects.get" }""")
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, Gap)
    assert r.event["method"] == "SetIamPolicy"  # the verified v1 name is preferred
    assert r.event["event_type"] == "USER_RESOURCE_UPDATE_PERMISSIONS"
    labels = r.event["udm"]
    assert labels["target.resource.attribute.labels[ser_binding_deltas_action]"] in ("ADD", "REMOVE")
    assert labels["target.resource.attribute.labels[ser_binding_deltas_role]"].startswith("roles/")
    assert "admin" in labels["target.resource.attribute.labels[ser_binding_deltas_member]"] or "@" in labels[
        "target.resource.attribute.labels[ser_binding_deltas_member]"
    ]
    assert not r.caveats and not r.approximate


def test_delta_rule_forces_values_not_absence():
    # A rule on ADD+owner: the solver may no longer dodge it by omitting the delta labels; the
    # witness must carry a *different* action or role.
    lib = _lib(
        """
        detection owner_added {
          event method = "SetIamPolicy"
            and udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD"
            and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
        }
        """
    )
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, Gap)
    labels = r.event["udm"]
    assert (
        labels["target.resource.attribute.labels[ser_binding_deltas_action]"] != "ADD"
        or labels["target.resource.attribute.labels[ser_binding_deltas_role]"] != "roles/owner"
    )


def test_unverified_method_witness_is_approximate_with_caveat():
    from dataclasses import replace

    lib = _lib("""detection d { event method = "storage.objects.get" }""")
    acct = _account("resourcemanager.projects.setIamPolicy")
    acct = replace(acct, logging=replace(acct.logging, disabled_methods=frozenset({"SetIamPolicy"})))
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, Gap)
    assert r.event["method"] == "google.cloud.resourcemanager.v3.Projects.SetIamPolicy"
    assert r.approximate and r.caveats and "not confirmed" in r.caveats[0]


def test_unverified_method_cannot_be_the_reason_for_a_gap():
    # The rule watches the confirmed v1 name; the catalog also lists an unverified v3 spelling.
    # The solver must not "find" a gap by switching to the unverified name.
    lib = _lib("""detection d { event method = "SetIamPolicy" }""")
    acct = _account("resourcemanager.projects.setIamPolicy")
    r = find_gap("resourcemanager.projects.setIamPolicy", lib, acct)
    assert isinstance(r, NoGap) and r.reason == "all_covered"


def test_witness_resource_is_one_the_principal_reaches():
    # the grant is scoped to a project and a rule reads `resource`: the witness must carry a
    # resource the principal really reaches, not "" (which Reach rejects, looping to exhaustion)
    lib = _lib('''detection d { event method = "storage.objects.get" and resource like "projects/secret*" }''')
    acct = Account(
        name="t",
        bindings={"u": (Grant(permission="storage.objects.get", resource="projects/demo"),)},
        logging=LogConfig(admin_activity=True, data_access_services=frozenset({"storage.googleapis.com"})),
        catalog=Catalog.seed(),
    )
    ctx = CoverageContext(lib)
    r = find_gap("storage.objects.get", lib, acct, ctx=ctx)
    assert isinstance(r, Gap) and r.event["resource"] == "projects/demo"
    assert ctx.stats["checks"] <= 3 and acct.reach("u", "storage.objects.get", r.event["resource"])

"""The GCP catalog built from the iam-dataset: seed entries win, generated names start
unverified, rules attest names, roles expand in account files."""

from __future__ import annotations

from decnique.env.catalog import Catalog
from decnique.env.ingest import account_from_dict
from decnique.env.model import Account, Grant


def test_gcp_catalog_merges_seed_and_dataset():
    c = Catalog.gcp()
    assert len(c.by_method) > 10_000 and len(c.all_permissions()) > 4_000
    seed = c.info("SetIamPolicy")
    assert seed and seed.verified and seed.source == "seed"
    gen = c.info("storage.buckets.setIamPolicy")
    assert gen and not gen.verified and gen.source == "generated"
    assert gen.permissions == ("storage.buckets.setIamPolicy",) and gen.service == "storage.googleapis.com"
    # every generated spelling of one API method maps to the same permissions
    assert c.info("google.cloud.resourcemanager.v3.Projects.SetIamPolicy").permissions == ("resourcemanager.projects.setIamPolicy",)
    assert c.permissions_for("no.such.method") is None
    assert "cloudkms.cryptoKeyVersions.useToDecrypt" in c.all_permissions()


def test_attest_marks_rule_named_methods_verified():
    c = Catalog.gcp()
    a = c.attest(["storage.buckets.setIamPolicy", "no.such.method"])
    assert a.verified("storage.buckets.setIamPolicy") and a.info("storage.buckets.setIamPolicy").source == "rules"
    assert not c.verified("storage.buckets.setIamPolicy")  # the original is untouched
    assert not a.known("no.such.method")


def test_roles_and_tags():
    owner = Catalog.role_permissions("roles/owner")
    assert owner and "resourcemanager.projects.setIamPolicy" in owner
    assert Catalog.role_permissions("roles/nope") is None
    assert "iam.serviceAccountKeys.create" in Catalog.tags()["CredentialExposure"]


def test_account_file_expands_predefined_roles():
    acct = account_from_dict({"version": 1, "bindings": {"a@x.com": [{"role": "roles/iam.serviceAccountKeyAdmin", "resource": "projects/p"}]}})
    assert acct.reach("a@x.com", "iam.serviceAccountKeys.create", "projects/p")
    assert acct.reach("a@x.com", "iam.serviceAccountKeys.create")  # "*" = on some resource
    assert not acct.reach("a@x.com", "iam.serviceAccountKeys.create", "projects/other")
    assert not acct.reach("a@x.com", "resourcemanager.projects.setIamPolicy")
    custom = account_from_dict({"version": 1, "roles": {"roles/x": ["a.b.c"]}, "bindings": {"u": [{"role": "roles/x"}]}})
    assert custom.reach("u", "a.b.c")


def test_scoped_grant_is_reachable_somewhere():
    acct = Account(bindings={"u": (Grant(permission="storage.objects.get", resource="projects/demo"),)})
    assert acct.reachable("storage.objects.get") and acct.principals_with("storage.objects.get") == ("u",)

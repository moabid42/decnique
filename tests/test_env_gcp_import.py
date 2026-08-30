"""Raw gcloud exports load as accounts: roles expand, members keep their audit-log spelling,
Data Access logging comes from auditConfigs, and everything not modelled is a note."""

from __future__ import annotations

from decnique.env import load_account, normalize_account_doc
from decnique.ui.repl import dispatch
from decnique.ui.session import Session

_POLICY = "tests/fixtures/gcloud_policy.json"
_ASSETS = "tests/fixtures/gcloud_assets.json"


def test_iam_policy_import():
    acct = load_account(_POLICY, resource="projects/demo")
    assert acct.reach("admin@demo.com", "resourcemanager.projects.setIamPolicy", "projects/demo")
    assert acct.reach("ci@demo.iam.gserviceaccount.com", "iam.serviceAccountKeys.create", "projects/demo")
    assert not acct.reach("ci@demo.iam.gserviceaccount.com", "resourcemanager.projects.setIamPolicy")
    assert acct.reach("allUsers", "storage.objects.get", "projects/demo")
    assert acct.reach("temp@demo.com", "resourcemanager.projects.get")  # conditional binding kept (noted)
    assert "gone@demo.com" not in acct.bindings and "domain:demo.com" in acct.bindings
    assert acct.logged("storage.objects.get") and not acct.logged("iam.serviceAccounts.getAccessToken")
    doc = normalize_account_doc(__import__("json").load(open(_POLICY)), resource="projects/demo")
    notes = " ".join(doc["notes"])
    assert "conditional binding" in notes and "exempted" in notes and "domain:demo.com" in notes


def test_asset_search_import_scopes_grants_per_resource():
    acct = load_account(_ASSETS)
    bucket = "//storage.googleapis.com/projects/_/buckets/secrets"
    assert acct.reach("reader@demo.iam.gserviceaccount.com", "storage.objects.get", bucket)
    assert not acct.reach("reader@demo.iam.gserviceaccount.com", "storage.objects.get", "projects/123")
    assert acct.reach("admin@demo.com", "storage.buckets.delete", bucket)  # project owner reaches the child bucket
    assert acct.hierarchy[bucket] == "projects/123"
    assert not acct.logged("storage.objects.get")  # no auditConfigs in an asset search → off


def test_account_verb_accepts_raw_exports_and_runs(tmp_path):
    s = Session()
    assert dispatch(s, f"account {_POLICY} projects/demo") is True and s.account is not None
    assert s.account.reach("admin@demo.com", "resourcemanager.projects.setIamPolicy", "projects/demo")
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    assert dispatch(s, "blindspots iam.serviceAccountKeys.create") is True
    assert dispatch(s, f"account {_ASSETS}") is True and s.account.name == "gcloud_assets"

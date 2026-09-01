"""Terraform loads as an account: `terraform show -json` (resolved state/plan) and native
`*.tf.json` config both convert to the account document.  IAM bindings become grants scoped
to their resource, custom roles expand, audit configs drive Data Access logging, data sources
are ignored, and anything unresolved (`${...}`) is kept but flagged approximate."""

from __future__ import annotations

import json

from decnique.env import load_account, normalize_account_doc
from decnique.ui.repl import dispatch
from decnique.ui.session import Session

_SHOW = "tests/fixtures/terraform_show.json"
_CONFIG = "tests/fixtures/terraform_config.tf.json"
_BUCKET = "//storage.googleapis.com/projects/_/buckets/secrets"


def test_terraform_show_state_import():
    acct = load_account(_SHOW)
    # member + binding grants, members keep audit-log spelling (user:/serviceAccount:/group: stripped)
    assert acct.reach("admin@demo.com", "resourcemanager.projects.setIamPolicy", "projects/demo")
    assert acct.reach("ci@demo.iam.gserviceaccount.com", "iam.serviceAccountKeys.create", "projects/demo")
    assert "sec@demo.com" in acct.bindings
    # custom role permissions expand for a binding that references it by its full IAM id
    assert acct.reach("bob@demo.com", "compute.instances.create", "projects/demo")
    assert not acct.reach("bob@demo.com", "storage.objects.get", "projects/demo")
    # a resource-level grant is scoped to its bucket, not the project
    assert acct.reach("reader@demo.iam.gserviceaccount.com", "storage.objects.get", _BUCKET)
    assert not acct.reach("reader@demo.iam.gserviceaccount.com", "storage.objects.get", "projects/other")
    # data sources are not grants
    assert "ghost@demo.com" not in acct.bindings
    # Data Access logging comes from the audit config; exempted member is a note
    assert acct.logged("storage.objects.get")
    doc = normalize_account_doc(json.load(open(_SHOW)))
    assert any("exempted" in n for n in doc["notes"])


def test_terraform_native_config_import_flags_unresolved():
    acct = load_account(_CONFIG)
    assert acct.reach("carol@demo.com", "compute.instances.get", "projects/demo")
    assert acct.reach("dave@demo.com", "resourcemanager.projects.setIamPolicy", "projects/demo")
    doc = normalize_account_doc(json.load(open(_CONFIG)))
    assert any("unresolved reference" in n for n in doc["notes"])


def test_account_verb_accepts_terraform_and_runs():
    s = Session()
    assert dispatch(s, f"account load {_SHOW}") is True and s.account is not None
    assert s.account.name == "terraform_show"
    assert s.account.reach("admin@demo.com", "resourcemanager.projects.setIamPolicy", "projects/demo")
    dispatch(s, 'detection keys { event method = "google.iam.admin.v1.CreateServiceAccountKey" }')
    assert dispatch(s, "ask blindspots iam.serviceAccountKeys.create") is True
    assert dispatch(s, f"account load {_CONFIG}") is True

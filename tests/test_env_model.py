"""M1 acceptance: the account model answers Reach / Log / hierarchy on a fixture table."""

from __future__ import annotations

import pytest

from decnique.env import Catalog, account_from_dict, load_account
from decnique.env.model import Account, Deny, Grant, LogConfig

_DOC = {
    "version": 1,
    "name": "prod",
    "roles": {"roles/storageAdmin": ["storage.buckets.setIamPolicy", "storage.objects.get"]},
    "bindings": {
        "alice@example.com": [
            {"permission": "iam.serviceAccounts.getAccessToken", "resource": "projects/p"},
            {"role": "roles/storageAdmin", "resource": "projects/p"},
        ],
        "bob@example.com": [
            {"permission": "iam.serviceAccountKeys.create", "resource": "*"},
        ],
    },
    "hierarchy": {
        "//storage.googleapis.com/projects/p/buckets/b": "projects/p",
        "projects/p": "folders/f",
    },
    "deny": [{"principal": "bob@example.com", "permission": "iam.serviceAccountKeys.create",
              "resource": "projects/locked"}],
    "logging": {
        "admin_activity": True,
        "data_access_services": ["storage.googleapis.com"],
        "disabled_methods": ["google.iam.credentials.v1.GenerateAccessToken"],
    },
    "access_levels": ["trusted"],
}


@pytest.fixture()
def account() -> Account:
    return account_from_dict(_DOC)


# --- reach -------------------------------------------------------------------------------


def test_reach_direct_grant(account):
    assert account.reach("alice@example.com", "iam.serviceAccounts.getAccessToken", "projects/p")


def test_reach_denied_when_not_granted(account):
    assert not account.reach("bob@example.com", "iam.serviceAccounts.getAccessToken", "projects/p")


def test_reach_via_role_expansion(account):
    assert account.reach("alice@example.com", "storage.objects.get", "projects/p")


def test_reach_through_hierarchy(account):
    # alice's grant is at projects/p; the bucket is a child → covered
    bucket = "//storage.googleapis.com/projects/p/buckets/b"
    assert account.reach("alice@example.com", "storage.objects.get", bucket)


def test_reach_out_of_scope_resource(account):
    # a project alice has no grant on
    assert not account.reach("alice@example.com", "storage.objects.get", "projects/other")


def test_deny_overrides_grant(account):
    assert account.reach("bob@example.com", "iam.serviceAccountKeys.create", "projects/p")
    assert not account.reach("bob@example.com", "iam.serviceAccountKeys.create", "projects/locked")


def test_reachable_and_principals(account):
    assert account.reachable("iam.serviceAccountKeys.create")
    assert account.principals_with("storage.objects.get", "projects/p") == ("alice@example.com",)
    assert not account.reachable("compute.instances.create")


def test_principals_with_all(account):
    both = ("iam.serviceAccounts.getAccessToken", "storage.objects.get")
    assert account.principals_with_all(both, "projects/p") == ("alice@example.com",)
    assert account.principals_with_all(("iam.serviceAccountKeys.create", "storage.objects.get")) == ()


# --- log ---------------------------------------------------------------------------------


def test_admin_activity_always_logged(account):
    # a SetIamPolicy admin-activity method is logged
    assert account.logged("google.iam.admin.v1.SetIAMPolicy")


def test_data_access_logged_only_for_enabled_service(account):
    # storage data-access is enabled → logged
    assert account.logged("storage.objects.get") is True
    # secretmanager data-access is NOT enabled → blind spot
    assert account.logged(
        "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
    ) is False


def test_disabled_method_is_a_blind_spot(account):
    assert account.logged("google.iam.credentials.v1.GenerateAccessToken") is False


def test_unlogged_methods_listing(account):
    methods = (
        "google.iam.admin.v1.SetIAMPolicy",  # logged
        "google.iam.credentials.v1.GenerateAccessToken",  # disabled
        "storage.objects.get",  # logged
    )
    assert account.unlogged_methods(methods) == ("google.iam.credentials.v1.GenerateAccessToken",)


# --- catalog -----------------------------------------------------------------------------


def test_catalog_known_method_permissions():
    cat = Catalog.seed()
    assert cat.permissions_for("google.iam.admin.v1.CreateServiceAccountKey") == (
        "iam.serviceAccountKeys.create",
    )


def test_catalog_unknown_method_degrades_to_none():
    cat = Catalog.seed()
    assert cat.permissions_for("some.unknown.method.Foo") is None  # honesty, not a raise


def test_catalog_methods_for_permission():
    cat = Catalog.seed()
    methods = cat.methods_for("iam.serviceAccounts.getAccessToken")
    assert "iam.serviceAccounts.getAccessToken" in methods


# --- round-trip through ingest -----------------------------------------------------------


def test_account_roundtrips_through_file(tmp_path):
    import json

    p = tmp_path / "acct.json"
    p.write_text(json.dumps(_DOC), encoding="utf-8")
    acct = load_account(p)
    assert acct.name == "prod"
    assert acct.reach("alice@example.com", "iam.serviceAccounts.getAccessToken", "projects/p")


def test_unsupported_schema_version_raises():
    from decnique.env import AccountSchemaError

    with pytest.raises(AccountSchemaError):
        account_from_dict({"version": 99, "bindings": {}})

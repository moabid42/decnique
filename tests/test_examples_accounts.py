"""The bundled example accounts must stay valid and keep teaching what their comments claim.
These use only the bundled catalog (seed or gcp), so they run with or without the corpus."""

import glob
import json

import pytest

from decnique.env.ingest import load_account

ACCOUNTS = sorted(glob.glob("examples/accounts/custom/*.json"))
SECRET_METHOD = "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"


def test_there_are_several_example_accounts():
    assert len(ACCOUNTS) >= 6


@pytest.mark.parametrize("path", ACCOUNTS)
def test_account_is_valid_json_and_loads(path):
    json.loads(open(path, encoding="utf-8").read())  # valid JSON (comments live in _comment/_expect)
    acc = load_account(path)
    assert acc.bindings, f"{path} has no principals"


def test_data_access_off_makes_secret_read_unlogged():
    off = load_account("examples/accounts/custom/03_data_access_off.json")
    on = load_account("examples/accounts/custom/04_data_access_on.json")
    assert off.logged(SECRET_METHOD) is False
    assert on.logged(SECRET_METHOD) is True


def test_scoped_grant_is_scoped():
    a = load_account("examples/accounts/custom/06_scoped_grant.json")
    p = "scoped-admin@demo.com"
    assert a.reach(p, "resourcemanager.projects.setIamPolicy", "projects/demo") is True
    assert a.reach(p, "resourcemanager.projects.setIamPolicy", "projects/other") is False


def test_deny_and_exemption():
    a = load_account("examples/accounts/custom/07_deny_and_exemption.json")
    p = "breaker@demo.com"
    # deny wins on the locked project, grant stands elsewhere
    assert a.reach(p, "resourcemanager.projects.setIamPolicy", "projects/locked") is False
    assert a.reach(p, "resourcemanager.projects.setIamPolicy", "projects/other") is True
    # the single secret method is exempted even though data-access logging is on
    assert a.logged(SECRET_METHOD) is False

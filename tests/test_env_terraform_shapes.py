"""Terraform shapes the bundled fixtures do not cover.

`tests/test_env_terraform_import.py` walks two realistic documents end to end.  This one goes
the other way: one small document per branch of the importer, because the branches that never
run on the fixtures are exactly the ones that could silently drop a grant — and a dropped
grant makes an account look *safer* than it is (invariant #1 again, on the Reach side).
"""

from __future__ import annotations

import json

import pytest

from decnique.env import account_doc_from_terraform, looks_like_terraform


def _state(*resources: dict, child: tuple[dict, ...] = ()) -> dict:
    root = {"resources": list(resources)}
    if child:
        root["child_modules"] = [{"resources": list(child)}]
    return {"values": {"root_module": root}}


def _res(rtype: str, **values) -> dict:
    return {"type": rtype, "mode": "managed", "values": values}


# --- recognising a document ---------------------------------------------------------------


@pytest.mark.parametrize(
    "doc",
    [
        {"resource": {"google_project_iam_member": {}}},
        {"values": {"root_module": {}}},
        {"planned_values": {"root_module": {}}},
    ],
)
def test_terraform_documents_are_recognised(doc):
    assert looks_like_terraform(doc) is True


@pytest.mark.parametrize("doc", [{}, [], "text", None, {"version": 1, "bindings": {}}, {"values": {}}])
def test_anything_else_is_not_terraform(doc):
    assert looks_like_terraform(doc) is False


def test_a_non_dict_is_refused_rather_than_half_read():
    with pytest.raises(ValueError):
        account_doc_from_terraform(["not", "a", "document"])


# --- where the resources live -------------------------------------------------------------


def test_a_plan_is_read_from_planned_values():
    doc = {"planned_values": {"root_module": {"resources": [
        _res("google_project_iam_member", project="demo", role="roles/viewer", member="user:a@x.com")
    ]}}}
    assert "a@x.com" in account_doc_from_terraform(doc)["bindings"]


def test_grants_inside_child_modules_are_not_lost():
    doc = _state(
        _res("google_project_iam_member", project="demo", role="roles/viewer", member="user:root@x.com"),
        child=(_res("google_project_iam_member", project="demo", role="roles/owner", member="user:deep@x.com"),),
    )
    assert set(account_doc_from_terraform(doc)["bindings"]) == {"root@x.com", "deep@x.com"}


def test_data_sources_are_not_grants():
    doc = {"values": {"root_module": {"resources": [
        {"type": "google_project_iam_member", "mode": "data",
         "values": {"project": "demo", "role": "roles/owner", "member": "user:ghost@x.com"}},
    ]}}}
    assert account_doc_from_terraform(doc)["bindings"] == {}


def test_a_config_block_may_repeat_a_resource_name():
    doc = {"resource": {"google_project_iam_member": {
        "grants": [
            {"project": "demo", "role": "roles/viewer", "member": "user:one@x.com"},
            {"project": "demo", "role": "roles/viewer", "member": "user:two@x.com"},
        ]
    }}}
    assert set(account_doc_from_terraform(doc)["bindings"]) == {"one@x.com", "two@x.com"}


def test_an_account_with_no_grants_says_so_instead_of_looking_clean():
    doc = account_doc_from_terraform(_state(_res("google_storage_bucket", name="b")))
    assert doc["bindings"] == {}
    assert any("no google_*_iam_* grants found" in n for n in doc["notes"])


def test_non_google_resources_are_ignored():
    doc = account_doc_from_terraform(_state(_res("aws_iam_role", name="r")))
    assert doc["bindings"] == {} and doc["roles"] == {}


# --- scoping ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("values", "scope"),
    [
        ({"project": "demo"}, "projects/demo"),
        ({"project": "projects/demo"}, "projects/demo"),
        ({"folder": "1234"}, "folders/1234"),
        ({"folder": "folders/1234"}, "folders/1234"),
        ({"org_id": "9876"}, "organizations/9876"),
        ({"bucket": "b/secrets"}, "b/secrets"),
        ({"secret_id": "s/api-key"}, "s/api-key"),
    ],
)
def test_a_grant_is_scoped_to_the_resource_the_type_names(values, scope):
    doc = _state(_res("google_project_iam_member", role="roles/owner", member="user:a@x.com", **values))
    grants = account_doc_from_terraform(doc)["bindings"]["a@x.com"]
    assert {g["resource"] for g in grants} == {scope}


def test_an_unrecognised_scope_widens_the_grant_and_is_noted():
    """Scoping to ``*`` over-approximates Reach, which is the safe direction — but the reader
    has to be told, or they would read the result as precise."""
    doc = account_doc_from_terraform(
        _state(_res("google_thing_iam_member", role="roles/owner", member="user:a@x.com"))
    )
    assert {g["resource"] for g in doc["bindings"]["a@x.com"]} == {"*"}
    assert any("scope not recognised" in n for n in doc["notes"])


def test_a_binding_carries_every_member():
    doc = _state(_res("google_project_iam_binding", project="demo", role="roles/viewer",
                      members=["user:a@x.com", "serviceAccount:b@x.iam.gserviceaccount.com", ""]))
    assert set(account_doc_from_terraform(doc)["bindings"]) == {"a@x.com", "b@x.iam.gserviceaccount.com"}


def test_an_unresolved_reference_is_kept_and_flagged():
    doc = account_doc_from_terraform(
        _state(_res("google_project_iam_member", project="demo", role="roles/owner",
                    member="user:${var.admin}"))
    )
    assert any("unresolved reference" in n for n in doc["notes"])
    assert doc["bindings"], "the grant is kept — dropping it would hide reachable permissions"


# --- policies, roles, audit configs ---------------------------------------------------------


def test_a_policy_resource_brings_its_bindings_and_audit_configs():
    policy = {
        "bindings": [{"role": "roles/owner", "members": ["user:root@x.com"]}],
        "auditConfigs": [{"service": "storage.googleapis.com",
                          "auditLogConfigs": [{"logType": "DATA_READ"}]}],
    }
    doc = account_doc_from_terraform(
        _state(_res("google_project_iam_policy", project="demo", policy_data=json.dumps(policy)))
    )
    assert "root@x.com" in doc["bindings"]
    assert doc["logging"]["data_access_services"] == ["storage.googleapis.com"]


def test_a_policy_given_as_a_dict_works_too():
    policy = {"bindings": [{"role": "roles/owner", "members": ["user:root@x.com"]}]}
    doc = _state(_res("google_project_iam_policy", project="demo", policy_data=policy))
    assert "root@x.com" in account_doc_from_terraform(doc)["bindings"]


def test_unreadable_policy_data_is_skipped_with_a_note_not_a_crash():
    doc = account_doc_from_terraform(
        _state(_res("google_project_iam_policy", project="demo", policy_data="{not json"))
    )
    assert doc["bindings"] == {}
    assert any("not readable JSON" in n for n in doc["notes"])


def test_an_empty_policy_resource_is_ignored():
    assert account_doc_from_terraform(
        _state(_res("google_project_iam_policy", project="demo"))
    )["bindings"] == {}


@pytest.mark.parametrize(
    ("values", "full"),
    [
        ({"project": "demo"}, "projects/demo/roles/deployer"),
        ({"org_id": "9876"}, "organizations/9876/roles/deployer"),
        ({}, "deployer"),
    ],
)
def test_a_custom_role_is_registered_under_its_full_id_and_its_short_one(values, full):
    doc = _state(_res("google_project_iam_custom_role", role_id="deployer",
                      permissions=["compute.instances.create"], **values))
    roles = account_doc_from_terraform(doc)["roles"]
    assert roles[full] == ["compute.instances.create"]
    assert roles["deployer"] == ["compute.instances.create"]


def test_a_custom_role_without_an_id_is_skipped():
    doc = _state(_res("google_project_iam_custom_role", permissions=["x.y.z"]))
    assert account_doc_from_terraform(doc)["roles"] == {}


def test_an_audit_config_turns_data_access_logging_on():
    doc = _state(_res("google_project_iam_audit_config", project="demo",
                      service="secretmanager.googleapis.com",
                      audit_log_config=[{"log_type": "DATA_READ"}]))
    assert account_doc_from_terraform(doc)["logging"]["data_access_services"] == [
        "secretmanager.googleapis.com"
    ]


def test_admin_activity_logging_is_always_assumed_on():
    """GCP cannot switch it off, so the model does not offer a way to."""
    assert account_doc_from_terraform(_state())["logging"]["admin_activity"] is True


# --- hierarchy ------------------------------------------------------------------------------


def test_a_project_records_its_parent_folder_or_org():
    under_folder = _state(_res("google_project", project_id="demo", folder_id="1234"))
    assert account_doc_from_terraform(under_folder)["hierarchy"] == {"projects/demo": "folders/1234"}
    under_org = _state(_res("google_project", project_id="demo", org_id="9876"))
    assert account_doc_from_terraform(under_org)["hierarchy"] == {
        "projects/demo": "organizations/9876"
    }


def test_a_project_with_no_parent_adds_nothing():
    assert account_doc_from_terraform(_state(_res("google_project", project_id="demo")))["hierarchy"] == {}
    assert account_doc_from_terraform(_state(_res("google_project")))["hierarchy"] == {}


def test_a_folder_records_its_parent():
    doc = _state(_res("google_folder", name="1234", parent="organizations/9876"))
    assert account_doc_from_terraform(doc)["hierarchy"] == {"folders/1234": "organizations/9876"}


def test_a_folder_without_a_parent_adds_nothing():
    assert account_doc_from_terraform(_state(_res("google_folder", name="1234")))["hierarchy"] == {}


def test_the_document_is_named_so_reports_can_tell_accounts_apart():
    assert account_doc_from_terraform(_state(), name="prod-state")["name"] == "prod-state"
    assert account_doc_from_terraform(_state())["version"] == 1

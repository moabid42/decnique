"""Turn Terraform (infrastructure as code) into the account document
:mod:`decnique.env.ingest` understands — the IAM side only.

Terraform *describes the account* (who is granted what, what is audit-logged); it does not
describe detections.  A SecOps rule can be wrapped in a ``google_chronicle_rule`` resource,
but the rule body there is just YARA-L text the ``secops`` front-end already reads — so
detections keep loading through ``rules load`` on native files, and this importer only builds
``Reach`` / ``Log``.

Two JSON inputs, no HCL parsing (raw ``.tf`` needs a real HCL parser and still can't resolve
``var`` / ``for_each`` / modules, which would silently drop grants — Invariant #1):

- **resolved state / plan** — ``terraform show -json`` (everything expanded).  The resources
  live under ``values.root_module`` (state) or ``planned_values.root_module`` (a plan), nested
  through ``child_modules``.  This is the honest input: every value is concrete.
- **native JSON config** — a ``*.tf.json`` file: ``{"resource": {TYPE: {NAME: {...attrs}}}}``.
  Values here may still be ``${...}`` references; those are kept literally and noted approximate.

GCP IAM resources are recognised by suffix, so every service is covered by one rule:

- ``google_*_iam_member`` / ``google_*_iam_binding`` — a grant, scoped to its resource;
- ``google_*_iam_policy`` — the ``policy_data`` JSON (bindings + auditConfigs), scoped likewise;
- ``google_*_iam_audit_config`` — Data Access logging (``DATA_READ`` / ``DATA_WRITE``);
- ``google_*_iam_custom_role`` — a role's ``permissions`` (added to the role catalog);
- ``google_project`` / ``google_folder`` — resource hierarchy (best effort).

What is kept honest rather than guessed matches :mod:`decnique.env.gcp_import`: members keep
their audit-log spelling, opaque members stay markers, conditional bindings are kept
unconditionally and noted, exempted audit members are noted.
"""

from __future__ import annotations

import json
from typing import Any

from decnique.env.gcp_import import _bindings_into, _logging_of

# Resource-level (non project/folder/org) IAM types name the scoped resource in one of these
# attributes; ``bucket`` for a storage bucket, ``crypto_key_id`` for a KMS key, and so on.
_RESOURCE_SCOPE_KEYS = (
    "bucket", "service_account_id", "crypto_key_id", "key_ring_id", "dataset_id", "table_id",
    "topic", "subscription", "secret_id", "instance", "instance_name", "repository",
    "registry", "queue", "database", "cluster", "function", "service", "job", "name",
)


def looks_like_terraform(doc: Any) -> bool:
    """A ``terraform show -json`` document (state or plan) or a native ``*.tf.json`` config."""
    if not isinstance(doc, dict):
        return False
    if isinstance(doc.get("resource"), dict):
        return True
    for key in ("values", "planned_values"):
        v = doc.get(key)
        if isinstance(v, dict) and "root_module" in v:
            return True
    return False


def _resources_from_module(module: dict) -> list[tuple[str, dict]]:
    """Managed resources in a ``show -json`` module, recursing into child modules."""
    out: list[tuple[str, dict]] = []
    for r in module.get("resources", []) or []:
        if not isinstance(r, dict) or "type" not in r:
            continue
        if r.get("mode", "managed") != "managed":  # skip data sources
            continue
        out.append((r["type"], r.get("values") or {}))
    for child in module.get("child_modules", []) or []:
        if isinstance(child, dict):
            out.extend(_resources_from_module(child))
    return out


def _resources_from_config(resource_block: dict) -> list[tuple[str, dict]]:
    """Managed resources in a ``*.tf.json`` ``resource`` block: ``{TYPE: {NAME: attrs|[attrs]}}``."""
    out: list[tuple[str, dict]] = []
    for rtype, named in resource_block.items():
        if not isinstance(named, dict):
            continue
        for attrs in named.values():
            for a in (attrs if isinstance(attrs, list) else [attrs]):
                if isinstance(a, dict):
                    out.append((rtype, a))
    return out


def _all_resources(doc: dict) -> list[tuple[str, dict]]:
    if isinstance(doc.get("resource"), dict):
        return _resources_from_config(doc["resource"])
    for key in ("values", "planned_values"):
        v = doc.get(key)
        if isinstance(v, dict) and isinstance(v.get("root_module"), dict):
            return _resources_from_module(v["root_module"])
    return []


def _prefixed(value: Any, prefix: str) -> str:
    """``my-proj`` → ``projects/my-proj``; leaves an already-qualified value alone."""
    s = str(value)
    return s if s.startswith(prefix) else f"{prefix}{s}"


def _scope_of(values: dict) -> str | None:
    """The resource a grant is scoped to; ``None`` if the type is not one we recognise."""
    if values.get("project"):
        return _prefixed(values["project"], "projects/")
    if values.get("folder"):
        return _prefixed(values["folder"], "folders/")
    if values.get("org_id"):
        return _prefixed(values["org_id"], "organizations/")
    for k in _RESOURCE_SCOPE_KEYS:
        if values.get(k):
            return str(values[k])
    return None


def _members_of(rtype: str, values: dict) -> list[str]:
    if rtype.endswith("_iam_member"):
        return [values["member"]] if values.get("member") else []
    return [m for m in (values.get("members", []) or []) if m]


def _handle(
    rtype: str,
    values: dict,
    bindings: dict[str, list[dict]],
    roles: dict[str, tuple[str, ...]],
    hierarchy: dict[str, str],
    da_services: set[str],
    notes: list[str],
) -> None:
    if not rtype.startswith("google_"):
        return

    if rtype.endswith("_iam_custom_role"):
        rid = values.get("role_id")
        if not rid:
            return
        perms = tuple(values.get("permissions", []) or [])
        if values.get("project"):
            full = f"projects/{values['project']}/roles/{rid}"
        elif values.get("org_id"):
            full = f"organizations/{values['org_id']}/roles/{rid}"
        else:
            full = rid
        roles[full] = perms
        roles.setdefault(rid, perms)
        return

    if rtype.endswith("_iam_audit_config"):
        configs = [
            {"logType": c.get("log_type"), "exemptedMembers": c.get("exempted_members", []) or []}
            for c in (values.get("audit_log_config", []) or [])
        ]
        ac = {"service": values.get("service", ""), "auditLogConfigs": configs}
        da_services.update(_logging_of([ac], notes)["data_access_services"])
        return

    if rtype.endswith("_iam_policy"):
        pd = values.get("policy_data")
        if not pd:
            return
        try:
            policy = json.loads(pd) if isinstance(pd, str) else pd
        except (ValueError, TypeError):
            notes.append(f"{rtype}: policy_data is not readable JSON (skipped)")
            return
        scope = _scope_of(values) or "*"
        _bindings_into(bindings, notes, policy.get("bindings", []) or [], scope)
        da_services.update(_logging_of(policy.get("auditConfigs", []) or [], notes)["data_access_services"])
        return

    if rtype.endswith("_iam_member") or rtype.endswith("_iam_binding"):
        role = values.get("role", "")
        members = _members_of(rtype, values)
        scope = _scope_of(values)
        if scope is None:
            scope = "*"
            notes.append(f"{rtype}: resource scope not recognised; grant scoped to any resource (approximate)")
        for m in members:
            if isinstance(m, str) and "${" in m:
                notes.append(f"{rtype}: member '{m}' is an unresolved reference (approximate)")
        _bindings_into(bindings, notes, [{"role": role, "members": members}], scope)
        return

    if rtype == "google_project":
        pid = values.get("project_id")
        if not pid:
            return
        if values.get("folder_id"):
            hierarchy[f"projects/{pid}"] = _prefixed(values["folder_id"], "folders/")
        elif values.get("org_id"):
            hierarchy[f"projects/{pid}"] = _prefixed(values["org_id"], "organizations/")
        return

    if rtype == "google_folder":
        fid = values.get("name") or values.get("folder_id")
        parent = values.get("parent")
        if fid and parent:
            hierarchy[_prefixed(fid, "folders/")] = str(parent)
        return


def account_doc_from_terraform(doc: Any, *, name: str = "terraform") -> dict:
    """The versioned account document for a Terraform state/plan JSON or a ``*.tf.json`` config."""
    if not isinstance(doc, dict):
        raise ValueError("not a Terraform document")
    bindings: dict[str, list[dict]] = {}
    roles: dict[str, tuple[str, ...]] = {}
    hierarchy: dict[str, str] = {}
    da_services: set[str] = set()
    notes: list[str] = []

    resources = _all_resources(doc)
    for rtype, values in resources:
        _handle(rtype, values, bindings, roles, hierarchy, da_services, notes)

    if not bindings:
        notes.append("no google_*_iam_* grants found — is this a GCP Terraform state/config?")

    logging = {
        "admin_activity": True,
        "data_access_services": sorted(da_services),
        "disabled_methods": [],
    }
    return {
        "version": 1,
        "name": name,
        "roles": {r: list(p) for r, p in roles.items()},
        "bindings": bindings,
        "hierarchy": hierarchy,
        "logging": logging,
        "notes": notes,
    }

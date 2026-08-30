"""Turn real GCP exports into the account document :mod:`decnique.env.ingest` understands.

Two inputs, one ``gcloud`` command each:

- an **IAM policy** — ``gcloud projects get-iam-policy PROJECT --format=json`` (also folders /
  organizations): ``{"bindings": [{"role", "members", "condition"?}], "auditConfigs": [...]}``.
  ``auditConfigs`` is where Data Access logging lives, so ``Log`` comes from the same file.
- **Cloud Asset Inventory** — ``gcloud asset search-all-iam-policies --scope=… --format=json``:
  a list of ``{"resource": "//service/…", "policy": {"bindings": [...]}}``, one per resource
  that carries a policy, so grants are scoped to the resource they were found on.

What is kept honest rather than guessed:

- members keep their audit-log spelling (``user:a@b`` → ``a@b``; ``allUsers`` stays);
  ``domain:`` / ``principalSet:`` members cannot be enumerated and are kept as a marker
  principal (a reach through them is reported approximate by the UI);
- a binding with an IAM ``condition`` is kept **unconditionally** (Reach may be wider than
  reality) and listed in ``notes`` — nothing here evaluates CEL;
- ``exemptedMembers`` of an audit config are listed in ``notes``, not modelled.
"""

from __future__ import annotations

from typing import Any

_KEEP_AS_IS = ("allUsers", "allAuthenticatedUsers")
_OPAQUE = ("domain:", "principalSet:", "principal:", "projectOwner:", "projectEditor:", "projectViewer:")


def looks_like_iam_policy(doc: Any) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("bindings"), list) and all(
        isinstance(b, dict) and "members" in b for b in doc["bindings"]
    )


def looks_like_asset_search(doc: Any) -> bool:
    return isinstance(doc, list) and bool(doc) and all(
        isinstance(x, dict) and "resource" in x and "policy" in x for x in doc
    )


def principal_of(member: str) -> str:
    """``user:a@b`` → ``a@b`` (what ``authenticationInfo.principalEmail`` carries)."""
    if member in _KEEP_AS_IS or member.startswith(_OPAQUE):
        return member
    if member.startswith("deleted:"):
        return ""
    return member.split(":", 1)[1] if ":" in member else member


def _resource_of_asset(res: str) -> str:
    """``//cloudresourcemanager.googleapis.com/projects/123`` → ``projects/123``; other
    services keep the full ``//…`` name (that is what a bucket-level grant is scoped to)."""
    if res.startswith("//cloudresourcemanager.googleapis.com/"):
        return res.split("/", 3)[3]
    return res


def _bindings_into(out: dict[str, list[dict]], notes: list[str], bindings: list[dict], resource: str) -> None:
    for b in bindings:
        role = b.get("role", "")
        if b.get("condition"):
            title = b["condition"].get("title") or b["condition"].get("expression", "")[:60]
            notes.append(f"conditional binding kept unconditionally: {role} on {resource} ({title})")
        for m in b.get("members", []):
            p = principal_of(m)
            if not p:
                continue
            if p.startswith(_OPAQUE):
                notes.append(f"member {m} cannot be enumerated; kept as a marker principal")
            out.setdefault(p, []).append({"role": role, "resource": resource})


def _logging_of(audit_configs: list[dict], notes: list[str]) -> dict:
    services: set[str] = set()
    for ac in audit_configs or []:
        svc = ac.get("service", "")
        for lc in ac.get("auditLogConfigs", []):
            if lc.get("logType") in ("DATA_READ", "DATA_WRITE"):
                services.add("*" if svc == "allServices" else svc)
            for ex in lc.get("exemptedMembers", []) or []:
                notes.append(f"{svc} {lc.get('logType')}: {ex} is exempted from logging (not modelled)")
    return {"admin_activity": True, "data_access_services": sorted(services), "disabled_methods": []}


def account_doc_from_gcp(doc: Any, *, resource: str = "*", name: str = "gcp") -> dict:
    """The versioned account document for an IAM policy or an asset-search export."""
    bindings: dict[str, list[dict]] = {}
    notes: list[str] = []
    hierarchy: dict[str, str] = {}
    if looks_like_iam_policy(doc):
        _bindings_into(bindings, notes, doc["bindings"], resource)
        logging = _logging_of(doc.get("auditConfigs", []), notes)
    elif looks_like_asset_search(doc):
        logging = {"admin_activity": True, "data_access_services": [], "disabled_methods": []}
        for asset in doc:
            res = _resource_of_asset(asset["resource"])
            _bindings_into(bindings, notes, asset["policy"].get("bindings", []), res)
            proj = asset.get("project")
            if proj and proj != res:
                hierarchy[res] = proj
            for ac in asset["policy"].get("auditConfigs", []) or []:
                for svc in _logging_of([ac], notes)["data_access_services"]:
                    if svc not in logging["data_access_services"]:
                        logging["data_access_services"].append(svc)
        if not any(a["policy"].get("auditConfigs") for a in doc):
            notes.append("asset search carries no auditConfigs: Data Access logging assumed OFF "
                         "(import the project IAM policy to get it)")
    else:
        raise ValueError("not a gcloud IAM policy (bindings with members) nor an asset-search export")
    return {"version": 1, "name": name, "bindings": bindings, "hierarchy": hierarchy,
            "logging": logging, "notes": notes}

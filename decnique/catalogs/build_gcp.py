"""Build decnique's GCP catalog files from the iam-dataset (``gcp/`` directory of
https://github.com/iann0036/iam-dataset).  Data in, data out — nothing here is used at run time.

    python -m decnique.catalogs.build_gcp /path/to/iam-dataset/gcp

Writes, next to this file:

- ``gcp_methods.json.gz`` — ``{api_method_id: {"permissions": [...], "low_confidence": [...],
  "service": host, "http": "POST", "names": [audit-log methodName candidates]}}``.  The
  ``names`` are *candidates* derived from the discovery document (see :func:`audit_names`); the
  run-time catalog marks them unverified until a rule or a real log attests them.
- ``gcp_roles.json.gz`` — ``{"roles/x": [permissions...]}`` for every predefined role.
- ``gcp_tags.json`` — the dataset's attack tags (PrivEsc / CredentialExposure / DataAccess).
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Verbs whose calls land in the *Data Access* audit log (off by default) rather than *Admin
# Activity*.  A heuristic from Google's own split ("reads of metadata/config and all data
# reads/writes"); the run-time catalog keeps it as a guess, not a fact.
_DATA_ACCESS_VERBS = {"get", "list", "getIamPolicy", "testIamPermissions", "read", "query",
                      "export", "download", "batchGet", "search", "generateAccessToken",
                      "generateIdToken", "signBlob", "signJwt", "access", "getData", "watch"}
_DATA_ACCESS_PREFIXES = ("storage.objects.", "bigquery.tables.getData", "bigquery.jobs.query")


def _iam_prefix(host: str, mapping: dict) -> str:
    api = host.split(".")[0]
    return mapping.get("api", {}).get(api, api)


def _permission_name(raw: str, mapping: dict) -> str:
    """``iam.googleapis.com-workforcePools.create`` → ``iam.workforcePools.create``."""
    if ".googleapis.com-" in raw:
        host, rest = raw.split("-", 1)
        return f"{_iam_prefix(host, mapping)}.{rest}"
    return raw


def audit_names(method_id: str, entry: dict, preferred: str) -> list[str]:
    """Candidate ``protoPayload.methodName`` spellings for one API method.

    Three conventions occur in Cloud Audit Logs:

    1. the discovery id itself (``storage.objects.get``, ``google.logging.v2.…`` services that
       expose gRPC-style ids do the same);
    2. the gRPC full name from ``apiPaths`` with the version filled in
       (``google/cloud/resourcemanager/{_version}/Projects/SetIamPolicy`` →
       ``google.cloud.resourcemanager.v3.Projects.SetIamPolicy``);
    3. Compute's ``<version>.<id>`` (``v1.compute.instances.insert``, ``beta.…``).
    """
    names = [method_id]
    versions = [v for v in entry.get("versions", []) if v] or [preferred or "v1"]
    for p in entry.get("apiPaths", []) or []:
        for v in versions:
            names.append(p.replace("{_version}", v).replace("/", "."))
    if method_id.startswith("compute."):
        for v in versions:
            names.append(f"{v}.{method_id}")
    return list(dict.fromkeys(n for n in names if n))


def build(dataset: Path) -> dict[str, int]:
    mapping = json.loads((dataset / "service_mapping.json").read_text())
    api = json.loads((dataset / "map.json").read_text())["api"]
    ext = json.loads((dataset / "methods_ext.json").read_text())
    methods: dict[str, dict] = {}
    for svc, block in api.items():
        info = ext.get(svc, {})
        preferred = info.get("preferredVersion", "")
        host = f"{svc}.googleapis.com"
        for mid, m in (block.get("methods") or {}).items():
            perms, low = [], []
            for p in m.get("permissions", []) or []:
                name = _permission_name(p["name"], mapping)
                (low if p.get("lowConfidence") else perms).append(name)
            entry = (info.get("methods") or {}).get(mid, {})
            verb = entry.get("method") or mid.rsplit(".", 1)[-1]
            data_access = verb in _DATA_ACCESS_VERBS or mid.startswith(_DATA_ACCESS_PREFIXES) \
                or entry.get("httpMethod") == "GET"
            methods[mid] = {
                "permissions": list(dict.fromkeys(perms)),
                "low_confidence": [x for x in dict.fromkeys(low) if x not in perms],
                "service": host,
                "http": entry.get("httpMethod", ""),
                "data_access": bool(data_access),
                "names": audit_names(mid, entry, preferred),
            }
    roles: dict[str, list[str]] = {}
    for f in sorted((dataset / "roles").glob("*.json")):
        doc = json.loads(f.read_text())
        roles[doc["name"]] = sorted(doc.get("includedPermissions", []))
    tags = json.loads((dataset / "tags.json").read_text())

    with gzip.open(HERE / "gcp_methods.json.gz", "wt", encoding="utf-8") as fh:
        json.dump(methods, fh, separators=(",", ":"), sort_keys=True)
    with gzip.open(HERE / "gcp_roles.json.gz", "wt", encoding="utf-8") as fh:
        json.dump(roles, fh, separators=(",", ":"), sort_keys=True)
    (HERE / "gcp_tags.json").write_text(json.dumps(tags, indent=1, sort_keys=True) + "\n")
    return {"methods": len(methods), "with_permissions": sum(1 for m in methods.values() if m["permissions"]),
            "roles": len(roles), "permissions": len({p for m in methods.values() for p in m["permissions"]})}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(build(Path(sys.argv[1])))

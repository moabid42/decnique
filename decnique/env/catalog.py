"""Method ↔ permission catalog (plan §M1).

Connects a *rule's* world (audit-log ``method`` names) to an *account's* world (IAM
``permission`` strings).  A method "checks" one or more permissions; a permission is
"exercised by" one or more methods.  GCP is many-to-many, but a small seed covers the
methods that actually appear in the corpus and the privilege-escalation techniques.

The catalog is deliberately *incomplete and honest*: :func:`Catalog.permissions_for`
returns ``None`` for a method it does not know, and every consumer treats ``None`` as
*approximate* rather than pretending the method checks nothing.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class MethodInfo:
    """What a catalog knows about one audit-log method."""

    method: str
    permissions: tuple[str, ...]
    service: str
    data_access: bool = False  # True → a Data-Access log (off by default in GCP)


# A seed catalog.  method -> (permissions it checks, service, is-data-access).
# Kept small and auditable; extend via a loaded JSON file for a real deployment.
_SEED: tuple[MethodInfo, ...] = (
    # --- IAM / service accounts (the privilege-escalation surface) ---
    MethodInfo(
        "google.iam.admin.v1.CreateServiceAccountKey",
        ("iam.serviceAccountKeys.create",),
        "iam.googleapis.com",
    ),
    MethodInfo(
        "google.iam.admin.v1.CreateServiceAccount",
        ("iam.serviceAccounts.create",),
        "iam.googleapis.com",
    ),
    MethodInfo(
        "google.iam.admin.v1.SetIAMPolicy",
        ("iam.serviceAccounts.setIamPolicy",),
        "iam.googleapis.com",
    ),
    MethodInfo(
        "SetIamPolicy",
        ("resourcemanager.projects.setIamPolicy",),
        "cloudresourcemanager.googleapis.com",
    ),
    MethodInfo(
        "google.iam.credentials.v1.GenerateAccessToken",
        ("iam.serviceAccounts.getAccessToken",),
        "iamcredentials.googleapis.com",
        data_access=True,
    ),
    MethodInfo(
        "iam.serviceAccounts.getAccessToken",
        ("iam.serviceAccounts.getAccessToken",),
        "iamcredentials.googleapis.com",
        data_access=True,
    ),
    MethodInfo(
        "google.iam.credentials.v1.SignBlob",
        ("iam.serviceAccounts.signBlob",),
        "iamcredentials.googleapis.com",
        data_access=True,
    ),
    MethodInfo(
        "google.iam.admin.v1.UpdateRole",
        ("iam.roles.update",),
        "iam.googleapis.com",
    ),
    # --- resource manager ---
    MethodInfo(
        "google.cloud.resourcemanager.v3.Projects.SetIamPolicy",
        ("resourcemanager.projects.setIamPolicy",),
        "cloudresourcemanager.googleapis.com",
    ),
    # --- compute (actAs escalation, metadata) ---
    MethodInfo(
        "v1.compute.instances.insert",
        ("compute.instances.create", "iam.serviceAccounts.actAs"),
        "compute.googleapis.com",
    ),
    MethodInfo(
        "v1.compute.instances.setMetadata",
        ("compute.instances.setMetadata",),
        "compute.googleapis.com",
    ),
    # --- storage (data exfiltration / public exposure) ---
    MethodInfo(
        "storage.objects.get",
        ("storage.objects.get",),
        "storage.googleapis.com",
        data_access=True,
    ),
    MethodInfo(
        "storage.objects.list",
        ("storage.objects.list",),
        "storage.googleapis.com",
        data_access=True,
    ),
    MethodInfo(
        "storage.setIamPermissions",
        ("storage.buckets.setIamPolicy",),
        "storage.googleapis.com",
    ),
    # --- logging (defense evasion) ---
    MethodInfo(
        "google.logging.v2.ConfigServiceV2.UpdateSink",
        ("logging.sinks.update",),
        "logging.googleapis.com",
    ),
    MethodInfo(
        "google.logging.v2.ConfigServiceV2.DeleteSink",
        ("logging.sinks.delete",),
        "logging.googleapis.com",
    ),
    # --- secret manager ---
    MethodInfo(
        "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
        ("secretmanager.versions.access",),
        "secretmanager.googleapis.com",
        data_access=True,
    ),
)


@dataclass(frozen=True, slots=True)
class Catalog:
    """A method↔permission map with an explicit *unknown* answer for missing methods."""

    by_method: Mapping[str, MethodInfo] = field(default_factory=dict)

    @classmethod
    def seed(cls) -> "Catalog":
        return cls(by_method={m.method: m for m in _SEED})

    @classmethod
    def load(cls, path: str | Path) -> "Catalog":
        """Load/extend the seed from a JSON file ``{method: {permissions, service, data_access}}``."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        merged = {m.method: m for m in _SEED}
        for method, info in raw.items():
            merged[method] = MethodInfo(
                method=method,
                permissions=tuple(info.get("permissions", ())),
                service=info.get("service", _service_of(method)),
                data_access=bool(info.get("data_access", False)),
            )
        return cls(by_method=merged)

    def known(self, method: str) -> bool:
        return method in self.by_method

    def info(self, method: str) -> MethodInfo | None:
        return self.by_method.get(method)

    def permissions_for(self, method: str) -> tuple[str, ...] | None:
        """Permissions a method checks, or ``None`` when the catalog does not know the
        method (→ the caller must treat coverage of it as *approximate*)."""
        m = self.by_method.get(method)
        return m.permissions if m else None

    def methods_for(self, permission: str) -> frozenset[str]:
        """Every known method that checks ``permission`` (may be empty)."""
        return frozenset(m.method for m in self.by_method.values() if permission in m.permissions)

    def service_of(self, method: str) -> str:
        m = self.by_method.get(method)
        return m.service if m else _service_of(method)

    def is_data_access(self, method: str) -> bool:
        m = self.by_method.get(method)
        return bool(m and m.data_access)

    def all_permissions(self) -> frozenset[str]:
        return frozenset(p for m in self.by_method.values() for p in m.permissions)


def _service_of(method: str) -> str:
    """Best-effort service guess from a method name (fallback only)."""
    head = method.split(".", 1)[0]
    return f"{head}.googleapis.com" if head and not head[0].isupper() else "unknown"

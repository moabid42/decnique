"""Load an :class:`~decnique.env.model.Account` from exported GCP artifacts (plan §M1).

The schema is deliberately explicit and versioned — the account model is *data*.  A real
GCP exporter (Cloud Asset Inventory for bindings + hierarchy, logging-config export for
``logging``) can emit this JSON later; for now it is hand-written for fixtures.

Schema (``version: 1``)::

    {
      "version": 1,
      "name": "prod-account",
      "roles": { "roles/editor": ["compute.*", "storage.*"] },     # optional role catalog
      "bindings": {
        "alice@example.com": [
          {"permission": "iam.serviceAccounts.getAccessToken", "resource": "*"},
          {"role": "roles/editor", "resource": "projects/p"}
        ]
      },
      "hierarchy": { "//storage.../buckets/b": "projects/p", "projects/p": "folders/f" },
      "deny": [ {"principal": "*", "permission": "iam.*", "resource": "projects/locked"} ],
      "logging": {
        "admin_activity": true,
        "data_access_services": ["storage.googleapis.com"],
        "disabled_methods": ["storage.objects.get"]
      },
      "access_levels": ["trusted"]
    }
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from decnique.env.catalog import Catalog
from decnique.env.model import Account, Deny, Grant, LogConfig

SCHEMA_VERSION = 1


class AccountSchemaError(ValueError):
    """The account document is malformed or an unsupported schema version."""


def account_from_dict(doc: Mapping[str, Any], *, catalog: Catalog | None = None) -> Account:
    version = doc.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise AccountSchemaError(f"unsupported account schema version {version!r}")

    roles: dict[str, tuple[str, ...]] = {
        r: tuple(perms) for r, perms in (doc.get("roles") or {}).items()
    }
    cat = catalog or Catalog.default()

    bindings: dict[str, tuple[Grant, ...]] = {}
    for principal, grants in (doc.get("bindings") or {}).items():
        out: list[Grant] = []
        for g in grants:
            resource = g.get("resource", "*")
            if "role" in g:
                perms = roles.get(g["role"])
                if perms is None:  # not declared in the file: a predefined role from the catalog
                    perms = cat.role_permissions(g["role"])
                for perm in perms or ():
                    out.append(Grant(permission=perm, resource=resource))
                if perms is None:  # unknown role → a single wildcard-ish marker
                    out.append(Grant(permission=g["role"], resource=resource))
            for perm in g.get("permissions", ()):
                out.append(Grant(permission=perm, resource=resource))
            if "permission" in g:
                out.append(Grant(permission=g["permission"], resource=resource))
        bindings[principal] = tuple(out)

    log = doc.get("logging") or {}
    logging = LogConfig(
        admin_activity=bool(log.get("admin_activity", True)),
        data_access_services=frozenset(log.get("data_access_services", ())),
        disabled_methods=frozenset(log.get("disabled_methods", ())),
    )
    deny = tuple(
        Deny(
            principal=d["principal"],
            permission=d["permission"],
            resource=d.get("resource", "*"),
        )
        for d in (doc.get("deny") or [])
    )
    return Account(
        name=doc.get("name", "account"),
        bindings=bindings,
        hierarchy=dict(doc.get("hierarchy") or {}),
        deny=deny,
        logging=logging,
        access_levels=frozenset(doc.get("access_levels", ())),
        catalog=cat,
    )


def load_account(path: str | Path, *, catalog: Catalog | None = None) -> Account:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return account_from_dict(doc, catalog=catalog)

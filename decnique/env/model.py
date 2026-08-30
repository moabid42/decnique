"""The environment / account model — ``Reach`` and ``Log`` of plan §M1, §2.

A blind spot is only real if the attacker can *cause* the event and it is *logged*
(Invariant #2).  :class:`Account` encodes exactly those two facts about one GCP account:

- ``reach(principal, permission, resource)`` — does the account actually grant it?
  (IAM bindings, resource-pattern scope, resource hierarchy, optional deny policies.)
- ``logged(method)`` — is an event with this method actually written to the audit logs?
  (admin-activity is always on; data-access is off by default; explicit exemptions.)

The account is *data*: build it in code for tests, or load it from an exported artifact
via :mod:`decnique.env.ingest`.  It carries a :class:`~decnique.env.catalog.Catalog` so it
can answer method-world questions (``logged(method)``) from permission-world facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from decnique.env.catalog import Catalog


@dataclass(frozen=True, slots=True)
class Grant:
    """One IAM grant: a principal may exercise ``permission`` on resources matching
    ``resource`` (a glob; ``*`` = any).  ``permission`` may itself be a glob (a role
    expanded to ``storage.*`` etc.)."""

    permission: str
    resource: str = "*"


@dataclass(frozen=True, slots=True)
class Deny:
    """A deny policy: ``principal`` is denied ``permission`` on ``resource`` (glob)."""

    principal: str
    permission: str
    resource: str = "*"


@dataclass(frozen=True, slots=True)
class LogConfig:
    """What the account actually writes to Cloud Audit Logs.

    In GCP, Admin-Activity logs are always on; Data-Access logs are **off by default**
    and enabled per service.  ``disabled_methods`` are explicit exemptions (e.g. an
    ``exemptedMembers`` config or a removed sink) — a first-class blind-spot source.
    """

    admin_activity: bool = True
    data_access_services: frozenset[str] = frozenset()
    disabled_methods: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class Account:
    name: str = "account"
    bindings: dict[str, tuple[Grant, ...]] = field(default_factory=dict)
    hierarchy: dict[str, str] = field(default_factory=dict)  # resource -> parent
    deny: tuple[Deny, ...] = ()
    logging: LogConfig = field(default_factory=LogConfig)
    access_levels: frozenset[str] = frozenset()
    catalog: Catalog = field(default_factory=Catalog.default)

    # -- reachability ----------------------------------------------------------------------

    def _ancestors(self, resource: str) -> list[str]:
        """``resource`` and every ancestor up the hierarchy (self first)."""
        chain = [resource]
        seen = {resource}
        cur = resource
        while cur in self.hierarchy:
            cur = self.hierarchy[cur]
            if cur in seen:  # defend against a malformed cycle
                break
            seen.add(cur)
            chain.append(cur)
        return chain

    def _denied(self, principal: str, permission: str, resource: str) -> bool:
        scope = self._ancestors(resource)
        for d in self.deny:
            if d.principal not in (principal, "*", "allUsers"):
                continue
            if not _perm_match(d.permission, permission):
                continue
            if any(_res_match(d.resource, r) for r in scope):
                return True
        return False

    def reach(self, principal: str, permission: str, resource: str = "*") -> bool:
        """``Reach``: does the account grant ``principal`` the ``permission`` on ``resource``?

        A grant applies if its permission glob covers ``permission`` and its resource glob
        covers ``resource`` **or an ancestor** of it (a project-level grant reaches child
        buckets).  ``resource="*"`` asks "on *some* resource": any grant of the permission
        counts, however narrowly scoped.  An applicable deny policy overrides."""
        grants = self.bindings.get(principal, ())
        if not grants:
            return False
        if self._denied(principal, permission, resource):
            return False
        scope = self._ancestors(resource)
        for g in grants:
            if not _perm_match(g.permission, permission):
                continue
            if resource == "*" or g.resource == "*" or any(_res_match(g.resource, r) for r in scope):
                return True
        return False

    def example_resources(self, principal: str, permission: str) -> tuple[str, ...]:
        """Concrete resources on which ``principal`` may exercise ``permission`` — one per
        grant, a glob instantiated (``projects/*`` → ``projects/example``).  For witnesses."""
        out: list[str] = []
        for g in self.bindings.get(principal, ()):
            if not _perm_match(g.permission, permission):
                continue
            r = g.resource.replace("*", "example") if g.resource != "*" else "projects/example"
            if self.reach(principal, permission, r) and r not in out:
                out.append(r)
        return tuple(out)

    def reachable(self, permission: str, resource: str = "*") -> bool:
        """Can *any* principal exercise ``permission`` on ``resource``?"""
        return any(self.reach(p, permission, resource) for p in self.bindings)

    def principals_with(self, permission: str, resource: str = "*") -> tuple[str, ...]:
        return tuple(p for p in self.bindings if self.reach(p, permission, resource))

    def principals_with_all(
        self, permissions: tuple[str, ...], resource: str = "*"
    ) -> tuple[str, ...]:
        """Principals holding *every* permission in ``permissions`` (for ``feasible``)."""
        return tuple(
            p for p in self.bindings if all(self.reach(p, perm, resource) for perm in permissions)
        )

    # -- logging ---------------------------------------------------------------------------

    def logged(self, method: str) -> bool:
        """``Log``: is an event with this ``method`` actually written to the audit logs?"""
        if method in self.logging.disabled_methods:
            return False
        if self.catalog.is_data_access(method):
            return self.catalog.service_of(method) in self.logging.data_access_services
        # admin-activity (or unknown → treated as admin-activity)
        return self.logging.admin_activity

    def unlogged_methods(self, methods: tuple[str, ...]) -> tuple[str, ...]:
        """Methods that would *not* be logged — blind spots independent of any rule."""
        return tuple(m for m in methods if not self.logged(m))


def _perm_match(grant_perm: str, wanted: str) -> bool:
    return grant_perm == wanted or ("*" in grant_perm and fnmatchcase(wanted, grant_perm))


def _res_match(grant_res: str, wanted: str) -> bool:
    return grant_res == wanted or fnmatchcase(wanted, grant_res)

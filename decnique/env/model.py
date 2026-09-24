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


DATA_ACCESS_TYPES = ("ADMIN_READ", "DATA_READ", "DATA_WRITE")


@dataclass(frozen=True, slots=True)
class AuditLogConfig:
    """One service/category configuration, scoped like IAM and carrying normalized principals."""

    service: str
    log_type: str
    resource: str = "*"
    exempted_members: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LogConfig:
    """What the account actually writes to Cloud Audit Logs.

    In GCP, Admin-Activity logs are always on; Data-Access logs are **off by default**
    and configured by service, category, resource and principal. ``audit_configs=None`` retains
    the legacy service-wide model; an explicit tuple, even empty, takes precedence.
    ``disabled_methods`` is an explicit local override, not an IAM principal exemption.
    """

    admin_activity: bool = True
    data_access_services: frozenset[str] = frozenset()
    disabled_methods: frozenset[str] = frozenset()
    audit_configs: tuple[AuditLogConfig, ...] | None = None


@dataclass
class Account:
    # not frozen/slots: dict fields already make it unhashable, and we cache a grant index
    name: str = "account"
    bindings: dict[str, tuple[Grant, ...]] = field(default_factory=dict)
    hierarchy: dict[str, str] = field(default_factory=dict)  # resource -> parent
    deny: tuple[Deny, ...] = ()
    logging: LogConfig = field(default_factory=LogConfig)
    access_levels: frozenset[str] = frozenset()
    catalog: Catalog = field(default_factory=Catalog.default)
    assumptions: tuple[str, ...] = ()  # unresolved import facts carried into every account-based verdict

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

    def _index(self, principal: str) -> tuple[dict[str, list[str]], list[Grant]]:
        """Per principal: exact permission → its grant resources, and the glob-permission grants.
        Cached — an owner holds thousands of grants and reach is asked per permission."""
        cache = self.__dict__.setdefault("_grant_index", {})
        idx = cache.get(principal)
        if idx is None:
            exact: dict[str, list[str]] = {}
            globs: list[Grant] = []
            for g in self.bindings.get(principal, ()):
                if "*" in g.permission:
                    globs.append(g)
                else:
                    exact.setdefault(g.permission, []).append(g.resource)
            idx = cache[principal] = (exact, globs)
        return idx

    def reach(self, principal: str, permission: str, resource: str = "*") -> bool:
        """``Reach``: does the account grant ``principal`` the ``permission`` on ``resource``?

        A grant applies if its permission glob covers ``permission`` and its resource glob
        covers ``resource`` **or an ancestor** of it (a project-level grant reaches child
        buckets).  ``resource="*"`` asks "on *some* resource": any grant of the permission
        counts, however narrowly scoped.  An applicable deny policy overrides."""
        exact, globs = self._index(principal)
        resources = exact.get(permission)
        if resources is None and not globs:
            return False
        if self._denied(principal, permission, resource):
            return False
        candidates = list(resources or ())
        candidates += [g.resource for g in globs if _perm_match(g.permission, permission)]
        if not candidates:
            return False
        if resource == "*" or "*" in candidates:
            return True
        scope = self._ancestors(resource)
        return any(_res_match(gr, r) for gr in candidates for r in scope)

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

    def reaches_anywhere(self, principal: str, permission: str) -> bool:
        """Some grant of ``permission`` to ``principal`` is unscoped (``resource="*"``)."""
        return any(
            g.resource == "*" and _perm_match(g.permission, permission)
            for g in self.bindings.get(principal, ())
        ) and not self._denied(principal, permission, "*")

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

    def audit_configs_for(self, method: str) -> tuple[AuditLogConfig, ...]:
        svc = self.catalog.service_of(method)
        info = self.catalog.info(method)
        return tuple(c for c in self.logging.audit_configs or () if c.service in ("*", svc)
                     and (not info or not info.log_type or c.log_type == info.log_type))

    def logging_caveats(self, methods) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        notes: list[str] = []
        for method in sorted(set(methods)):
            configs = self.audit_configs_for(method)
            if not configs or not self.catalog.is_data_access(method):
                continue
            info = self.catalog.info(method)
            if not info.log_type:
                notes.append(f"{method}: Data Access category is unverified; logging is approximate")
            if any("[" in c.resource for c in configs):
                notes.append(f"{method}: audit resource character classes require concrete replay")
            for c in configs:
                for member in c.exempted_members:
                    if ":" in member or member in ("allUsers", "allAuthenticatedUsers"):
                        notes.append(f"{method}: audit exemption {member} cannot be resolved to individual principals")
        return tuple(notes)

    def logged(self, method: str, *, principal: str | None = None, resource: str = "*") -> bool:
        """``Log`` for a concrete event; omitted principal/resource ask whether logging is possible.

        Unverified method categories conservatively admit any configured Data Access category;
        callers must carry :meth:`logging_caveats` rather than treating that as an exact fact.
        """
        if method in self.logging.disabled_methods:
            return False
        if self.catalog.is_data_access(method):
            if self.logging.audit_configs is not None:
                configs = [c for c in self.audit_configs_for(method)
                           if resource == "*" or any(_res_match(c.resource, r) for r in self._ancestors(resource))]
                if resource == "*":  # existential prefilter; exemptions may only cover some scopes
                    return any(principal is None or principal not in c.exempted_members for c in configs)
                return any(
                    any(c.log_type == category for c in configs) and
                    not any(c.log_type == category and principal in c.exempted_members for c in configs)
                    for category in DATA_ACCESS_TYPES
                )
            return ("*" in self.logging.data_access_services  # allServices
                    or self.catalog.service_of(method) in self.logging.data_access_services)
        # admin-activity (or unknown → treated as admin-activity)
        return self.logging.admin_activity

    def event_logged(self, event: dict) -> bool:
        """Concrete replay must retain both the actor and resource when evaluating Log."""
        return self.logged(str(event.get("method", "")), principal=event.get("principal"),
                           resource=str(event.get("resource") or "*"))

    def unlogged_methods(self, methods: tuple[str, ...]) -> tuple[str, ...]:
        """Methods that would *not* be logged — blind spots independent of any rule."""
        return tuple(m for m in methods if not self.logged(m))


def _perm_match(grant_perm: str, wanted: str) -> bool:
    return grant_perm == wanted or ("*" in grant_perm and fnmatchcase(wanted, grant_perm))


def _res_match(grant_res: str, wanted: str) -> bool:
    return grant_res == wanted or fnmatchcase(wanted, grant_res)

"""Browsing verbs — look things up without leaving the shell.

``perms``    browse permissions: by service, then by name; how they are logged, who holds
             them, which rules name their methods, which attack tag they carry.
``methods``  one permission → its audit-log methods, or one method → its facts.
``roles``    predefined roles: which permissions a role has, which roles grant a permission.
``who``      the loaded account: who holds a permission (and where), or what a principal holds.

Every listing is capped (``--limit N``, default 20; ``--all`` lifts it) and says how many
rows it hid, so a whole catalog never floods the screen.  None of these verbs needs the
solver; only ``who`` needs an account, only the RULES column needs loaded rules.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from rich.text import Text

from decnique.env.catalog import Catalog

from .render import _add, _table, console

DEFAULT_LIMIT = 20


def _opts(args: list[str]) -> tuple[list[str], dict[str, str | bool]]:
    """Split ``--limit N`` / ``--all`` / ``--tag T`` / ``--with P`` / ``--reachable`` /
    ``--unwatched`` from positional words."""
    words: list[str] = []
    opts: dict[str, str | bool] = {}
    it = iter(args)
    for a in it:
        if a == "--all":
            opts["limit"] = "0"
        elif a in ("--limit", "--tag", "--with"):
            opts[a[2:]] = next(it, "")
        elif a.startswith("--"):
            opts[a[2:]] = True
        else:
            words.append(a)
    return words, opts


def _limit(opts: dict) -> int:
    try:
        return int(opts.get("limit", DEFAULT_LIMIT))
    except ValueError:
        return DEFAULT_LIMIT


def _match(name: str, filt: str | None) -> bool:
    if not filt:
        return True
    if any(ch in filt for ch in "*?"):
        return fnmatchcase(name, filt) or fnmatchcase(name, filt + "*")
    return filt.lower() in name.lower()


def _hidden(shown: int, total: int, what: str) -> None:
    if total > shown:
        console.print(f"[muted]showing {shown} of {total} {what} — narrow the filter, "
                      f"or use --limit N / --all[/muted]")


def _catalog(s) -> Catalog:  # type: ignore[no-untyped-def]
    return s.account.catalog if s.account is not None else Catalog.default()


def _tag_of(perm: str, tags: dict[str, tuple[str, ...]]) -> str:
    return ", ".join(t for t, ps in tags.items() if perm in ps)


_LITERALS: dict[int, dict[str, frozenset[str]]] = {}  # id(lib) -> rule id -> method literals


def _rules_naming(s, methods) -> list[str]:  # type: ignore[no-untyped-def]
    """Rules whose literal method tests include one of ``methods`` (literals cached per library)."""
    if s.lib is None:
        return []
    from decnique.dsl.interpret import spec_methods_literal

    lits = _LITERALS.get(id(s.lib))
    if lits is None:
        _LITERALS.clear()
        lits = _LITERALS[id(s.lib)] = {d.id: frozenset(spec_methods_literal(d.spec)) for d in s.lib.detections}
    ms = set(methods)
    return [rid for rid, l in lits.items() if l and not l.isdisjoint(ms)]


def _log_word(cat: Catalog, s, methods) -> str:  # type: ignore[no-untyped-def]
    """admin / data / mixed, with ✓ when the account writes at least one of them."""
    kinds = {"data" if cat.is_data_access(m) else "admin" for m in methods}
    word = "mixed" if len(kinds) > 1 else next(iter(kinds), "—")
    if s.account is not None and any(s.account.logged(m) for m in methods):
        word += " ✓"
    return word


# --- perms ---------------------------------------------------------------------------------


def perms(s, args: list[str]) -> None:  # type: ignore[no-untyped-def]
    """Browse permissions.  No filter → one row per service (so you can drill down);
    a filter (substring or glob, e.g. ``iam.`` or ``*.setIamPolicy``) → one row per permission."""
    words, opts = _opts(args)
    cat = _catalog(s)
    tags = Catalog.tags()
    filt = words[0] if words else None
    tag = opts.get("tag")
    universe = sorted(cat.all_permissions())
    if tag:
        want = {t.lower(): t for t in tags}
        if str(tag).lower() not in want:
            console.print(f"[warn]unknown tag {tag!r}[/warn] — known: {', '.join(tags)}")
            return
        universe = [p for p in universe if p in tags[want[str(tag).lower()]]]
    if opts.get("reachable"):
        if s.account is None:
            console.print("[warn]--reachable needs an account[/warn] — run: [key]account load <file.json>[/key]")
            return
        universe = [p for p in universe if s.account.reachable(p)]
    if opts.get("unwatched"):
        if s.lib is None:
            console.print("[warn]--unwatched needs rules[/warn] — run: [key]rules load <paths…>[/key]")
            return
        universe = [p for p in universe if not _rules_naming(s, cat.methods_for(p))]

    if not filt and len(universe) > _limit(opts):  # top level: services (a small set lists directly)
        by_service: dict[str, list[str]] = {}
        for p in universe:
            by_service.setdefault(p.split(".", 1)[0], []).append(p)
        rows = sorted(by_service.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        limit = _limit(opts)
        t = _table(f"permissions by service — {len(universe)} permission(s), {len(rows)} service(s)",
                   [("SERVICE",), ("PERMS", "right"), ("REACHABLE", "right"), ("WATCHED", "right"), ("TAGGED", "right")],
                   caption="drill down: perms <service>.  ·  REACHABLE needs an account · WATCHED = some rule "
                           "names one of its methods (needs rules) · TAGGED = PrivEsc / CredentialExposure / DataAccess")
        for svc, ps in rows[: limit or None]:
            reach = sum(s.account.reachable(p) for p in ps) if s.account is not None else "—"
            watched = sum(bool(_rules_naming(s, cat.methods_for(p))) for p in ps) if s.lib is not None else "—"
            tagged = sum(bool(_tag_of(p, tags)) for p in ps)
            _add(t, svc, str(len(ps)), str(reach), str(watched), str(tagged) if tagged else "")
        console.print(t)
        _hidden(min(len(rows), limit or len(rows)), len(rows), "services")
        return

    matched = [p for p in universe if _match(p, filt)]
    if not matched:
        console.print(f"[muted]no permission matches {filt!r}[/muted]" if filt else "[muted]no permission left[/muted]")
        return
    limit = _limit(opts)
    t = _table((f"permissions matching {filt!r}" if filt else "permissions") + f" — {len(matched)}",
               [("PERMISSION",), ("METHODS", "right"), ("LOG",), ("RULES", "right"), ("WHO",), ("TAG",)],
               caption="METHODS = audit-log methods that check it · LOG admin/data (✓ = this account writes it) · "
                       "RULES = rules naming one of its methods · WHO = principals holding it  →  methods <perm>, who <perm>")
    for p in matched[: limit or None]:
        ms = cat.methods_for(p)
        who = ""
        if s.account is not None:
            holders = s.account.principals_with(p)
            who = ", ".join(holders[:2]) + (f" +{len(holders) - 2}" if len(holders) > 2 else "")
        rules = _rules_naming(s, ms)
        _add(t, p, str(len(ms)), _log_word(cat, s, ms),
             str(len(rules)) if s.lib is not None else "—", who or ("(nobody)" if s.account is not None else "—"),
             _tag_of(p, tags))
    console.print(t)
    _hidden(min(len(matched), limit or len(matched)), len(matched), "permissions")


# --- methods -------------------------------------------------------------------------------


def methods(s, args: list[str]) -> None:  # type: ignore[no-untyped-def]
    """``methods <permission>`` → its audit-log methods; ``methods <method>`` → that method's facts."""
    words, opts = _opts(args)
    cat = _catalog(s)
    if not words:
        console.print("[muted]usage:[/muted] catalog methods <permission | method> [--limit N]   "
                      "(e.g. methods iam.serviceAccountKeys.create)")
        return
    name = words[0]
    if cat.known(name):
        _method_card(s, cat, name)
        return
    ms = sorted(cat.methods_for(name))
    if not ms:
        near = [p for p in sorted(cat.all_permissions()) if _match(p, name)][:5]
        console.print(f"[muted]no catalog method exercises {name!r}[/muted]"
                      + (f" — did you mean: {', '.join(near)}" if near else ""))
        return
    limit = _limit(opts)
    t = _table(f"methods exercising {name}" + (f" — {len(ms)}" if len(ms) > 1 else ""),
               [("METHOD",), ("SERVICE",), ("LOG",), ("NAME",), ("RULES", "right"), ("REQUIRED FIELDS",)],
               caption="LOG: admin = always on · data = off unless enabled · ✓ = this account writes it · "
                       "NAME: verified = seen in real logs · RULES = rules that name this method  →  methods <method>")
    for m in ms[: limit or None]:
        log = "data" if cat.is_data_access(m) else "admin"
        if s.account is not None and s.account.logged(m):
            log += " ✓"
        req = ", ".join(f.split("labels[")[-1].rstrip("]") for f in cat.required_fields(m)) or "—"
        rules = _rules_naming(s, [m])
        _add(t, m, cat.service_of(m), log, "verified" if cat.verified(m) else "unverified",
             str(len(rules)) if s.lib is not None else "—", req)
    console.print(t)
    _hidden(min(len(ms), limit or len(ms)), len(ms), "methods")
    if s.account is not None:
        console.print(f"[muted]principals holding it: {', '.join(s.account.principals_with(name)) or '(none in this account)'}[/muted]")


def _method_card(s, cat: Catalog, m: str) -> None:  # type: ignore[no-untyped-def]
    info = cat.info(m)
    assert info is not None
    inv = cat.field_invariants(m)
    log = "data access (off unless enabled)" if info.data_access else "admin activity (always on)"
    if s.account is not None:
        log += "  ✓ written" if s.account.logged(m) else "  ✗ NOT written by this account"
    t = _table(f"method {m}", [("FACT",), ("VALUE",)])
    _add(t, "service", info.service)
    _add(t, "log", log)
    _add(t, "name", ("verified — seen in real logs" if info.verified else "unverified — a plausible spelling") + f"  (source: {info.source})")
    _add(t, "permissions", Text("\n".join(info.permissions) or "—", justify="left"))
    if info.low_confidence:
        _add(t, "maybe also", Text("\n".join(info.low_confidence), justify="left"))
    _add(t, "pinned fields", Text("\n".join(f"{k} = {v}" for k, v in inv.items()) or "—", justify="left"))
    req = cat.required_fields(m)
    _add(t, "always present", Text("\n".join(req) or "—", justify="left"))
    rules = _rules_naming(s, [m])
    _add(t, "rules naming it", Text("\n".join(rules) or ("(none)" if s.lib is not None else "— (no rules loaded)"), justify="left"))
    console.print(t)


# --- roles ---------------------------------------------------------------------------------


def roles(s, args: list[str]) -> None:  # type: ignore[no-untyped-def]
    """``roles [filter]`` lists predefined roles; ``roles roles/x [filter]`` its permissions;
    ``roles --with <perm>`` the roles that grant a permission."""
    words, opts = _opts(args)
    from decnique.env.catalog import _gcp_roles

    table = _gcp_roles()
    if not table:
        console.print("[warn]no role catalog[/warn] — catalogs/gcp_roles.json.gz is missing")
        return
    limit = _limit(opts)
    if opts.get("with"):
        perm = str(opts["with"])
        hits = sorted((r, ps) for r, ps in table.items() if perm in ps or any(_glob_grant(g, perm) for g in ps))
        if not hits:
            console.print(f"[muted]no predefined role grants {perm!r}[/muted]")
            return
        t = _table(f"roles granting {perm} — {len(hits)}", [("ROLE",), ("PERMS", "right")],
                   caption="PERMS = size of the role (smaller = tighter)")
        for r, ps in sorted(hits, key=lambda kv: len(kv[1]))[: limit or None]:
            _add(t, r, str(len(ps)))
        console.print(t)
        _hidden(min(len(hits), limit or len(hits)), len(hits), "roles")
        return
    if words and words[0] in table:
        role = words[0]
        ps = sorted(table[role])
        filt = words[1] if len(words) > 1 else None
        shown = [p for p in ps if _match(p, filt)]
        t = _table(f"{role} — {len(ps)} permission(s)" + (f", {len(shown)} matching {filt!r}" if filt else ""),
                   [("PERMISSION",), ("LOG",), ("RULES", "right"), ("TAG",)],
                   caption="LOG admin/data · RULES = rules naming one of its methods (needs rules) · "
                           "TAG = attack tag from the dataset")
        cat = _catalog(s)
        tags = Catalog.tags()
        for p in shown[: limit or None]:
            ms = cat.methods_for(p)
            rules = _rules_naming(s, ms)
            _add(t, p, _log_word(cat, s, ms), str(len(rules)) if s.lib is not None else "—", _tag_of(p, tags))
        console.print(t)
        _hidden(min(len(shown), limit or len(shown)), len(shown), "permissions")
        return
    filt = words[0] if words else None
    hits = sorted(r for r in table if _match(r, filt))
    if not hits:
        console.print(f"[muted]no role matches {filt!r}[/muted]")
        return
    tags = Catalog.tags()
    t = _table(f"predefined roles — {len(hits)}" + (f" matching {filt!r}" if filt else ""),
               [("ROLE",), ("PERMS", "right"), ("PRIVESC", "right"), ("CREDS", "right"), ("DATA", "right")],
               caption="how many of the role's permissions carry each attack tag  →  roles <role> [filter]")
    for r in hits[: limit or None]:
        ps = set(table[r])
        _add(t, r, str(len(ps)),
             str(len(ps & set(tags.get("PrivEsc", ())))) or "",
             str(len(ps & set(tags.get("CredentialExposure", ())))),
             str(len(ps & set(tags.get("DataAccess", ())))))
    console.print(t)
    _hidden(min(len(hits), limit or len(hits)), len(hits), "roles")


def _glob_grant(grant: str, perm: str) -> bool:
    return any(ch in grant for ch in "*?") and fnmatchcase(perm, grant)


# --- who -----------------------------------------------------------------------------------


def who(s, args: list[str]) -> None:  # type: ignore[no-untyped-def]
    """``who <permission>`` → principals holding it and on which resource;
    ``who <principal> [filter]`` → the grants that principal holds; ``who`` → every principal."""
    if not s.need_account():
        return
    words, opts = _opts(args)
    acc = s.account
    limit = _limit(opts)
    if not words:
        t = _table(f"principals in {acc.name} — {len(acc.bindings)}", [("PRINCIPAL",), ("GRANTS", "right"), ("RESOURCES",)],
                   caption="GRANTS = permission grants (a role expands to many)  →  who <principal>")
        rows = sorted(acc.bindings.items(), key=lambda kv: -len(kv[1]))
        for p, grants in rows[: limit or None]:
            res = sorted({g.resource for g in grants})
            _add(t, p, str(len(grants)), ", ".join(res[:3]) + (f" +{len(res) - 3}" if len(res) > 3 else ""))
        console.print(t)
        _hidden(min(len(rows), limit or len(rows)), len(rows), "principals")
        return
    name = words[0]
    if name in acc.bindings:
        filt = words[1] if len(words) > 1 else None
        grants = [g for g in acc.bindings[name] if _match(g.permission, filt)]
        t = _table(f"{name} — {len(grants)} grant(s)" + (f" matching {filt!r}" if filt else ""),
                   [("PERMISSION",), ("RESOURCE",)], caption="a permission with * is a role-wide glob")
        for g in sorted(grants, key=lambda g: g.permission)[: limit or None]:
            _add(t, g.permission, g.resource)
        console.print(t)
        _hidden(min(len(grants), limit or len(grants)), len(grants), "grants")
        return
    holders = acc.principals_with(name)
    if not holders:
        near = [p for p in acc.bindings if _match(p, name)]
        console.print(f"[muted]nobody in {acc.name} holds {name!r}[/muted]"
                      + (f" — principals matching it: {', '.join(near[:5])}" if near else ""))
        return
    t = _table(f"who holds {name} — {len(holders)}", [("PRINCIPAL",), ("VIA",), ("RESOURCE",)],
               caption="VIA = the grant that gives it (exact, or a glob from a role)")
    for p in holders[: limit or None]:
        via = [g for g in acc.bindings[p] if g.permission == name or _glob_grant(g.permission, name)]
        _add(t, p, ", ".join(sorted({g.permission for g in via})) or "?",
             ", ".join(sorted({g.resource for g in via})) or "*")
    console.print(t)
    _hidden(min(len(holders), limit or len(holders)), len(holders), "principals")

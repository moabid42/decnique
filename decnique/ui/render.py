"""Every verb's output, in one place.

Two families live here:

* **Listing verbs** (`rules`, `candidates`, `show`, `admits`, `event`, `trace`, `footprint`,
  `summary`) render session facts as tidy tables.
* **Math verbs** (`blindspots`, `stealth`, `chains`) run a proof and narrate it through a
  :class:`~decnique.ui.reason.Reasoner`, then close with a result table.

The math verbs deliberately drive the engine one item at a time and re-run the concrete oracle
in view of the user, so the "check mechanism" on screen *is* the soundness argument, not a
re-description of it.
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from decnique.dsl import format as fmt
from decnique.eval import fires, matches_footprint

from .format import cond_str, event_brief, footprint_str, window_str
from .reason import Reasoner
from .session import Session
from .theme import CHECK, approx_word, console, tri_word

# --- table helper -------------------------------------------------------------------------


def _table(title: str, columns, *, caption: str | None = None) -> Table:
    t = Table(
        title=Text(title, style="title"),
        title_justify="left",
        caption=Text(caption, style="muted") if caption else None,
        caption_justify="left",
        header_style="brand",
        border_style="rule",
        expand=False,
        pad_edge=False,
    )
    for spec in columns:
        name, *rest = spec if isinstance(spec, tuple) else (spec,)
        justify = rest[0] if rest else "left"
        t.add_column(name, justify=justify, overflow="fold")
    return t


def _cell(value) -> Text:
    """A cell that may be a plain string or a ``(text, style)`` pair."""
    if isinstance(value, tuple):
        return Text(value[0], style=value[1])
    return Text(str(value))


def _add(table: Table, *cells) -> None:
    table.add_row(*(_cell(c) for c in cells))


# --- listing verbs ------------------------------------------------------------------------


def rules(s: Session, filt: str | None) -> None:
    if not s.need_lib():
        return
    only_approx = bool(filt) and filt.startswith("~")
    if only_approx:
        filt = filt[1:]
    shown = [d for d in s.lib.detections if (not filt or filt in d.id) and (not only_approx or d.approximate)]
    if not shown:
        console.print(f"[muted]no detections match {filt!r}[/muted]" if filt
                      else "[muted]no detections loaded[/muted]")
        return
    approx = sum(bool(d.approximate) for d in shown)
    total = len(s.lib.detections)
    title = f"detections — {len(shown)}" + (f" of {total}" if filt else "") + f", {approx} approximate"
    t = _table(
        title,
        [("ID",), ("SOURCE",), ("TYPE",), ("#EV", "right"), ("WINDOW",), ("CONDITION",), ("STATUS",)],
        caption="TYPE event=single / correlation=multi · #EV event vars · WINDOW correlation span · "
                "~approx = carries an Unknown atom",
    )
    for d in shown:
        _add(
            t, d.id, d.source.frontend if d.source else "dsl", d.paradigm,
            str(len(d.spec.events)), window_str(d.spec), cond_str(d.spec.condition),
            approx_word(d.approximate),
        )
    console.print(t)


def candidates(s: Session) -> None:
    if not s.need_lib():
        return
    cands = s.lib.bundle.candidates
    if not cands:
        console.print("[muted]no candidates loaded — techniques come from .decn `candidate {…}` blocks[/muted]")
        return
    t = _table(
        f"candidates — {len(cands)} techniques",
        [("ID",), ("REQUIRES",), ("FOOTPRINT",), ("ORDER",), ("SPAN", "right")],
        caption="REQUIRES permissions the actor must hold · FOOTPRINT step×repeat (guards) · "
                "full detail: show <id>",
    )
    for c in cands:
        fp = c.footprint
        _add(
            t, c.id, ", ".join(r.permission for r in c.required) or "—",
            footprint_str(fp) if fp else "—",
            " < ".join(fp.order) if fp and fp.order else "—",
            f"{fp.span_seconds}s" if fp and fp.span_seconds is not None else "—",
        )
    console.print(t)


def show(s: Session, ident: str | None) -> None:
    if not s.need_lib() or not ident:
        console.print("[muted]usage:[/muted] show <detection-or-candidate-id>")
        return
    for d in s.lib.detections:
        if d.id == ident:
            src = d.source
            origin = f"{src.frontend}: {src.file}" + (f":{src.line}" if src.line else "") if src else None
            _print_source("detection", d.id, fmt.detection(d), approximate=d.approximate, origin=origin)
            _print_untranslated(d)
            return
    for c in s.lib.bundle.candidates:
        if c.id == ident:
            _print_source("candidate", c.id, fmt.candidate(c))
            return
    for c in s.lib.bundle.checks:
        if c.id == ident:
            _print_source("check", c.id, fmt.check(c))
            return
    console.print(f"[warn]no detection, candidate, or check named {ident!r}[/warn]")


def _print_source(kind: str, ident: str, text: str, *, approximate: bool = False, origin: str | None = None) -> None:
    tag = Text()
    tag.append(f"{kind}  ", style="muted")
    tag.append(ident, style="brand")
    if approximate:
        tag.append("   ~approx", style="approx")
    body = Text(text)
    if origin:  # the original rule's file, so the engineer can open it
        body.append(f"\n\n# source: {origin}", style="muted")
    console.print(
        Panel(
            body,
            title=tag,
            title_align="left",
            subtitle=Text("what decnique translated this rule to (canonical DSL)", style="muted"),
            subtitle_align="left",
            border_style="rule",
            padding=(0, 1),
        )
    )


# Human-readable reasons a construct could not be translated, keyed by label prefix.
_UNTRANSLATED_WHY: dict[str, str] = {
    "events:unparsed": "the event predicate could not be parsed into the model",
    "events:cross_variable": "compares fields across two event variables (a join the model can't express here)",
    "events:no_event_variable": "the rule declares no usable event variable",
    "match:unbound_placeholder": "the match section joins on a placeholder that maps to no event-model field",
    "match:event_variable": "the match key is an event variable rather than a field value",
    "match:anchor": "an anchored match window the model doesn't support",
    "match:window": "a match window form the model doesn't support",
    "match:no_window": "a multi-event correlation with no window to bound it",
    "secops:same_var_field_compare": "compares two fields of the same event (field-to-field, no literal)",
    "secops:cross_variable": "a cross-event-variable comparison (a join)",
    "secops:placeholder_op": "an operation on a placeholder the model can't interpret",
    "secops:placeholder_literal": "a placeholder bound to a literal in a way the model can't pin",
    "secops:placeholder_compare": "two placeholders compared to each other",
    "secops:in_ref_operand": "an `in %reference_list` used where the model expects a value",
    "secops:unparsed": "a statement that could not be parsed",
    "secops:unsupported": "a construct outside the model's grammar",
    "condition:unparsed": "the count/condition expression could not be parsed",
    "condition:unknown_count": "a count over something the model can't identify",
    "condition:unknown_variable": "the condition names an unknown event variable",
    "condition:partially_lowered": "only part of the condition could be lowered",
}


def _untranslated_rows(d) -> list[tuple[str, str, str]]:
    """(construct, detail, why) for everything the front-end could not translate on this rule."""
    from decnique.model.predicates import unknowns

    rows: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for lbl in d.source.unsupported if d.source else ():
        parts = lbl.split(":")
        key = ":".join(parts[:2]) if len(parts) >= 2 else parts[0]
        detail = ":".join(parts[2:]) if len(parts) > 2 else ""
        why = _UNTRANSLATED_WHY.get(key) or _UNTRANSLATED_WHY.get(parts[0]) or "unsupported construct"
        rows.append((key, detail, why))
        seen.add(key)
    # the raw text of any Unknown atom left in a predicate (extra detail beyond the label)
    for e in d.spec.events:
        for u in unknowns(e.pred):
            if u.label not in seen:
                rows.append((u.label, (u.raw or "")[:80], _UNTRANSLATED_WHY.get(u.label, "unsupported construct")))
                seen.add(u.label)
    return rows


def unknown_summary(lib, ids) -> str:  # type: ignore[no-untyped-def]
    """One line saying *why* these rules answered don't-know, grouped by the construct that
    made them approximate: "5 rules — Panther python logic ×3, ES|QL ×2 (rules ~ lists them)"."""
    from collections import Counter

    by = {d.id: d for d in lib.detections}
    reasons: Counter[str] = Counter()
    for rid in ids:
        d = by.get(rid)
        rows = _untranslated_rows(d) if d is not None else []
        reasons[rows[0][0] if rows else "unknown atom"] += 1
    parts = ", ".join(f"{k} ×{n}" for k, n in reasons.most_common(4))
    more = "" if len(reasons) <= 4 else f", +{len(reasons) - 4} more"
    return f"{len(ids)} rule(s) answered don't-know — {parts}{more}  (`rules ~` lists them, `show <id>` says why)"


def _print_untranslated(d) -> None:
    """Show what did NOT translate, so an approximate verdict is legible at the source."""
    rows = _untranslated_rows(d)
    if not rows:
        console.print("[safe]✓ fully translated — this rule is exact (no Unknown atoms).[/safe]")
        return
    placeholders = [e.name for e in d.spec.events
                    if type(e.pred).__name__ == "Const" and e.pred.value is False]
    t = _table(
        "not translated — why this rule is ~approximate",
        [("CONSTRUCT",), ("DETAIL",), ("WHY",)],
        caption="these became `unknown`, so the engine answers three-valued (yes/no/don't-know) "
                "rather than pretend to a false verdict"
                + (f" · event(s) dropped to `false`: {', '.join(placeholders)}" if placeholders else ""),
    )
    for construct, detail, why in rows:
        _add(t, (construct, "approx"), detail or "—", why)
    console.print(t)


def admits(s: Session, method: str | None) -> None:
    if not s.need_lib() or not method:
        console.print("[muted]usage:[/muted] admits <method>")
        return
    hits = list(s.lib.admitting(method))
    if not hits:
        console.print(f"[muted]no detection could involve {method!r}[/muted]")
        return
    t = _table(f"detections that could involve {method!r} — {len(hits)}",
               [("ID",), ("SOURCE",), ("TYPE",), ("STATUS",)])
    for d in hits:
        _add(t, d.id, d.source.frontend if d.source else "dsl", d.paradigm, approx_word(d.approximate))
    console.print(t)


def summary(s: Session) -> None:
    if not s.need_lib():
        return
    data = s.lib.summary()
    t = _table("corpus summary", [("METRIC",), ("VALUE", "right")])
    for k, v in data.items():
        _add(t, k, str(v))
    console.print(t)


def event(s: Session, file: str | None) -> None:
    if not s.need_lib() or not file:
        console.print("[muted]usage:[/muted] event <file.json>   (a single audit-log entry or event dict)")
        return
    import json
    from pathlib import Path

    from .session import _events_from

    raw = json.loads(Path(file).read_text(encoding="utf-8"))
    ev = _events_from(raw)[0]
    obs = s.lib.observing(ev)
    t = _table("single-event observation", [("FIELD",), ("VALUE",), ("MEANING",)])
    _add(t, "observed_by", ", ".join(obs.observed_by) or "(none)", "detections that match this event")
    _add(t, "fires_single", ", ".join(obs.fires_single) or "(none)", "single-event rules that fire on it")
    _add(t, "unknown", ", ".join(obs.unknown) or "(none)", "rules that returned don't-know")
    _add(t, "approximate", tri_word(obs.approximate), "any Unknown atom in play")
    console.print(t)


def trace(s: Session, show_all: bool) -> None:
    if not s.need_lib() or not s.need_events():
        return
    rows = []
    fired = unk = 0
    for d in s.lib.detections:
        t = fires(d.spec, s.events, ref_lists=s.lib.ref_lists)
        fired += t is True
        unk += t is None
        if t is not False or show_all:
            rows.append((d.id, tri_word(t), d.paradigm, approx_word(d.approximate)))
    console.print(f"[title]trace over {len(s.events)} events[/title] — "
                  f"[yes]{fired} fire[/yes], [unknown]{unk} unknown[/unknown]")
    if not rows:
        console.print("[muted]no detection fires or is uncertain (use `trace all` to see every rule)[/muted]")
        return
    table = _table("", [("ID",), ("FIRES",), ("TYPE",), ("STATUS",)])
    for r in rows:
        _add(table, *r)
    console.print(table)


def footprint(s: Session, ident: str | None) -> None:
    if not s.need_lib() or not s.need_events():
        return
    rows = []
    for c in s.lib.bundle.candidates:
        if (ident and c.id != ident) or not c.footprint:
            continue
        t = matches_footprint(c.footprint, s.events, ref_lists=s.lib.ref_lists)
        rows.append((c.id, tri_word(t), footprint_str(c.footprint)))
    if not rows:
        console.print("[muted]no candidates to match" + (f" for {ident!r}" if ident else "") + "[/muted]")
        return
    table = _table(f"footprint match over {len(s.events)} events",
                   [("CANDIDATE",), ("MATCHES",), ("FOOTPRINT",)])
    for r in rows:
        _add(table, *r)
    console.print(table)


# --- math verbs (narrated) ----------------------------------------------------------------


def _short(path: str) -> str:
    """Generic shortening of a field path for the screen (no vocabulary involved)."""
    return path.removeprefix("udm:").removeprefix("target.resource.attribute.")


def change_text(v) -> str:  # type: ignore[no-untyped-def]
    """A kind of change in the rules' own syntax, with shortened field paths."""
    from decnique.smt.coverage import describe_atom

    return "  ∧  ".join(_short(describe_atom(a)) for a in v.atoms)


def _redundant_single(v, all_verdicts) -> bool:  # type: ignore[no-untyped-def]
    """A single atom on a field that also appears in combinations says little alone; hide it."""
    if len(v.atoms) != 1:
        return False
    f = v.atoms[0].field
    return any(len(w.atoms) > 1 and f in {a.field for a in w.atoms} for w in all_verdicts)


def event_sentence(ev: dict) -> str:
    """The witness as one line: who, which method, and the informative fields — generic."""
    who, method = ev.get("principal", "someone"), ev.get("method", "?")
    skip = {"principal", "method", "permission", "granted", "service", "product_name", "time"}
    parts = []
    for k, v in ev.items():
        if k in skip or v in (None, "", 0, "0.0.0.0"):
            continue
        if isinstance(v, dict):
            parts += [f"{_short(kk)}={vv}" for kk, vv in v.items() if vv not in (None, "")]
        else:
            parts.append(f"{k}={v}")
    return f"{who} calls {method}" + (" with " + ", ".join(parts) if parts else "")


def _title(lib, rid: str) -> str:  # type: ignore[no-untyped-def]
    d = lib.get(rid)
    t = str(d.meta.get("title") or d.meta.get("rule_name") or "").strip()
    return f"{t} [{rid}]" if t and t != rid else rid


def config(s: Session, args: list[str]) -> None:
    """``config`` — list settings; ``config <key> <value>`` — set; ``config <key> reset``."""
    st = s.settings
    if not args:
        t = _table("settings", [("KEY",), ("VALUE",), ("ALLOWED",), ("WHAT IT DOES",)])
        for key, val, allowed, help_ in st.rows():
            _add(t, key, val, allowed, help_)
        console.print(t)
        console.print(f"[muted]stored in {st.path}[/muted]")
        return
    key = args[0]
    if len(args) == 1:
        try:
            console.print(f"{key} = [title]{st.get(key)}[/title]")
        except KeyError:
            console.print(f"[err]unknown setting[/err] {key}")
        return
    try:
        if args[1] == "reset":
            st.reset(key)
        else:
            st.set(key, args[1])
        console.print(f"[ok]{CHECK}[/ok] {key} = [title]{st.get(key)}[/title]")
    except (KeyError, ValueError) as e:
        console.print(f"[err]{e}[/err]")


def blindspots(s: Session, perms: list[str]) -> None:
    if not s.need_lib() or not s.need_account():
        return
    from decnique.smt.coverage import (
        CoverageContext, Gap, blind_region, dodged_conditions, find_gap, probe_atoms, rules_naming,
    )
    from decnique.smt.stealth import Evasive, stealth_feasible

    explain = s.settings.get("blindspots.explain")
    show_raw = s.settings.get("blindspots.raw") == "on"

    lib, account = s.lib, s.account
    single = [d for d in lib.detections if d.spec.is_single_event]
    ctx = CoverageContext(lib)  # rules are encoded once (atom abstraction) and shared
    if perms:
        permissions = list(perms)
    else:
        permissions = sorted(p for p in account.catalog.all_permissions() if account.reachable(p))

    with s.report("blindspots", perms) as rep:
        _blindspots(s, lib, account, single, ctx, permissions, explain, show_raw, rep)


def _blindspots(s, lib, account, single, ctx, permissions, explain, show_raw, rep) -> None:  # type: ignore[no-untyped-def]
    from decnique.smt.coverage import Gap, blind_region, dodged_conditions, find_gap, probe_atoms, rules_naming
    from decnique.smt.stealth import Evasive, stealth_feasible

    r = Reasoner()
    r.header(
        "blindspots",
        formula="find e :  Reach(e) ∧ Log(e) ∧ ¬( ⋁ Observes(R, e) )",
        subtitle=(
            "QUESTION: for each permission — is there ANY logged action using it that no rule "
            "catches?  (Not \"is the attack caught\" — that is `stealth`; its verdict is shown "
            "per permission below.)\n"
            f"{len(permissions)} permission(s) · {len(single)} single-event rule(s) · every "
            "example is replayed through the concrete oracle before it is believed"
        ),
    )

    gaps: list[dict] = []
    covered = inconclusive = unreachable = unlogged = 0
    # A whole account is thousands of permissions: explain a gap only when some rule names one
    # of its methods (otherwise there is nothing to explain — no rule looks there at all).
    many = len(permissions) > 20
    unnamed = 0
    r.fast = many  # no spinner per step: starting one costs more than the solve at this size

    for i, p in enumerate(permissions, 1):
        r.section(p, f"[{i}/{len(permissions)}]" if many else None)
        if not account.reachable(p):
            r.no("unreachable — no principal in this account can exercise it")
            unreachable += 1
            rep.add(p, "unreachable", "no principal in this account can exercise it")
            r.blank()
            continue
        principals = account.principals_with(p)
        r.ok(f"Reach: exercisable by {', '.join(principals)}")
        all_methods = sorted(account.catalog.methods_for(p))
        logged = [m for m in all_methods if account.logged(m)]
        if not logged:
            r.no(f"Log: none of {len(all_methods)} method(s) is audit-logged → invisible regardless of rules")
            unlogged += 1
            rep.add(p, "unlogged", f"none of {len(all_methods)} method(s) is audit-logged")
            r.blank()
            continue
        r.ok(f"Log: {len(logged)} of {len(all_methods)} method(s) audit-logged")
        r.math(f"solving  Reach ∧ Log ∧ ¬(⋁ Observes)  over {len(single)} single-event rule(s)")
        with r.thinking(f"searching for an event no rule observes over {len(ctx.table.vars)} "
                        "atoms (≤64 refinements)…"):
            res = find_gap(p, lib, account, ctx=ctx)
        if not isinstance(res, Gap):
            if res.reason == "all_covered":
                r.verdict_safe("covered — every reachable+logged event trips a rule (UNSAT after refinement)")
                covered += 1
            elif res.reason == "exhausted":
                r.verdict_muted("inconclusive — refinement bound exhausted (not a proof of coverage)")
                inconclusive += 1
            else:
                r.verdict_muted(res.reason)
                inconclusive += 1
            rep.add(p, res.reason, "covered by " + ", ".join(res.covered_by) if res.covered_by else "", covered_by=list(res.covered_by))
            r.blank()
            continue
        # Gap: replay the witness through the concrete oracle, in view.
        with r.thinking(f"replay: firing all {len(lib.detections)} rules on the witness…"):
            verdicts = {d.id: fires(d.spec, [res.event], ref_lists=lib.ref_lists) for d in lib.detections}
        n_fire = sum(v is True for v in verdicts.values())
        n_unk = sum(v is None for v in verdicts.values())
        if explain == "words":
            from .words import event_sentence as _plain_event

            r.note(f"example nobody catches: {_plain_event(res.event)}   (wording is hard-coded, IAM only)")
        else:
            r.note(f"example nobody catches: {event_sentence(res.event)}")
        if show_raw:
            r.note(f"raw: {event_brief(res.event)}")
        r.replay(f"replay: {n_fire}/{len(lib.detections)} rules fire, {n_unk} unknown → "
                 f"{'sound' if n_fire == 0 else 'REJECTED'}", sound=(n_fire == 0))
        if n_unk:
            r.note(unknown_summary(lib, [rid for rid, v in verdicts.items() if v is None]))
        for c in res.caveats:
            r.note(f"caveat: {c}")
        tag = "approximate" if res.approximate else "exact"
        # The witness is only the *simplest* unobserved event.  Explain the whole hole, the
        # way the user configured (`config blindspots.explain rules|formula|both`).
        logged = [m for m in account.catalog.methods_for(p) if account.logged(m)]
        naming = rules_naming(lib, logged, ctx=ctx)
        mode = explain if (naming or not many) else "none"
        if mode == "none":
            unnamed += 1
            r.no(f"no rule names any of its {len(logged)} logged method(s) — every use is unseen")
        if mode == "words":
            # HARD-CODED wording (ui/words.py): only IAM binding-delta fields get sentences
            from .words import change_sentence

            with r.thinking("which kinds of change are watched…"):
                verdicts = probe_atoms(p, lib, account, ctx=ctx)
            if verdicts:
                r.math("per kind of change t:  ∃ e : t(e) ∧ Reach ∧ Log ∧ ¬(⋁ Observes)   (plain words; hard-coded vocabulary)")
                shown = [v for v in verdicts if not _redundant_single(v, verdicts)]
                for v in sorted(shown, key=lambda v: (not v.covered, change_sentence(v))):
                    if v.covered:
                        r.ok(f"watched:    {change_sentence(v)}")
                    elif isinstance(v.result, Gap):
                        r.no(f"UNWATCHED:  {change_sentence(v)}")
                    else:
                        r.note(f"unclear:    {change_sentence(v)}  ({v.result.reason})")
        if mode in ("rules", "both"):
            with r.thinking("which kinds of change are watched, and by which rules…"):
                verdicts = probe_atoms(p, lib, account, ctx=ctx)
            if verdicts:
                r.math("per kind of change t (the rules' own tests):  ∃ e : t(e) ∧ Reach ∧ Log ∧ ¬(⋁ Observes)")
                shown = [v for v in verdicts if not _redundant_single(v, verdicts)]
                for v in sorted(shown, key=lambda v: (not v.covered, change_text(v))):
                    if v.covered:
                        by = ", ".join(_title(lib, rid) for rid in v.result.covered_by) or "(core empty)"
                        r.ok(f"watched:    {change_text(v)}\n        caught by: {by}")
                    elif isinstance(v.result, Gap):
                        dodged = dodged_conditions(lib, v.result.event, naming)
                        # the rules that came closest: fewest unmet conditions, at most three
                        near = sorted((c for c in dodged.items() if c[1]), key=lambda kv: len(kv[1]))[:3]
                        lines = [f"        nearest rule: {_title(lib, rid)} — still needs {' & '.join(_short(x) for x in c)}"
                                 for rid, c in near]
                        r.no("\n".join([f"UNWATCHED:  {change_text(v)}", *lines]))
                    else:
                        r.note(f"unclear:    {change_text(v)}  ({v.result.reason})")
        if mode in ("formula", "both"):
            with r.thinking("computing the blind region as a formula (prime implicants)…"):
                cubes = blind_region(p, lib, account, ctx=ctx)
            if cubes:
                r.math("blind region  =  Domain ∧ ¬(⋁ Observes)  as a DNF over the rules' tests:")
                for i, c in enumerate(cubes):
                    lead = "unobserved iff " if i == 0 else "            or  "
                    r.no(lead + _short(c.describe()) + ("" if c.proven else "   (not minimised)"))
                n_approx = len(ctx.single_rules) - len(ctx.exact_rules)
                r.note(f"every cube is proven against the {len(ctx.exact_rules)} exactly-translated rules; "
                       f"{n_approx} approximate rule(s) are left out and might observe more")
        verdicts = verdicts if mode in ("rules", "both", "words") else ()
        # And the techniques that need this permission — the attacker's actual payloads.
        techs = [c for c in lib.bundle.candidates if any(q.permission == p for q in c.required)]
        detected_techs = []
        for c in techs:
            sv = stealth_feasible(c, lib, account)
            if isinstance(sv, Evasive):
                r.no(f"the attack `{c.id}` you defined: NOT caught ({approx_word(sv.approximate)}) — see `stealth {c.id}`")
            elif sv.verdict == "always_detected":
                detected_techs.append(c.id)
                r.ok(f"the attack `{c.id}` you defined: caught by a rule (proof) — see `stealth {c.id}`")
            else:
                r.note(f"the attack `{c.id}` you defined: {sv.verdict}")
        n_unwatched = sum(1 for v in verdicts if isinstance(v.result, Gap) and not _redundant_single(v, verdicts))
        why = (f"{n_unwatched} kind(s) of change with this permission go unseen" if verdicts
               else "at least one action with this permission goes unseen")
        if detected_techs:
            why += f"; the attack(s) {', '.join(detected_techs)} are caught, other uses are not"
        r.verdict_gap(f"BLIND SPOT ({tag}) — {why}")
        gaps.append({"permission": p, "event": res.event, "approximate": res.approximate})
        rep.add(p, "gap", why, approximate=res.approximate, event=res.event, caveats=list(res.caveats),
                unwatched=[change_text(v) for v in verdicts if isinstance(v.result, Gap)],
                watched=[change_text(v) for v in verdicts if v.covered])
        r.blank()

    rep.summary = {"gaps": len(gaps), "covered": covered, "inconclusive": inconclusive,
                   "unreachable": unreachable, "unlogged": unlogged, "unnamed": unnamed,
                   "permissions": len(permissions), "single_event_rules": len(single)}
    console.print(
        f"[title]result[/title]  [gap]{len(gaps)} gaps[/gap] · "
        f"[safe]{covered} covered[/safe] · {inconclusive} inconclusive · "
        f"{unreachable} unreachable · {unlogged} unlogged"
        + (f"   ({unnamed} of the gaps: no rule names the method at all)" if many else "")
    )
    if many:
        _service_summary(rep)
    if gaps:
        cap = 60 if many else len(gaps)
        t = _table("blind spots" + (f" (first {cap} of {len(gaps)}; the report has all)" if len(gaps) > cap else ""),
                   [("PERMISSION",), ("METHOD",), ("PRINCIPAL",), ("STATUS",)])
        for g in gaps[:cap]:
            _add(t, g["permission"], g["event"].get("method", "—"), g["event"].get("principal", "—"),
                 approx_word(g["approximate"]))
        console.print(t)
    else:
        console.print("[safe]no blind spots for the probed permissions[/safe]")


def methods(s: Session, perm: str | None) -> None:
    """Catalog lookup: the audit-log methods that exercise a permission (or, with no argument,
    a permission's own facts) — for writing a candidate's footprint and `where` payload."""
    if not s.need_account():
        return
    cat = s.account.catalog
    if not perm:
        console.print("[muted]usage:[/muted] methods <permission>   (e.g. methods iam.serviceAccountKeys.create)")
        return
    ms = sorted(cat.methods_for(perm))
    if not ms:
        console.print(f"[muted]no catalog method exercises {perm!r}[/muted] "
                      "(the catalog is GCP; an unknown permission has no method)")
        return
    t = _table(f"methods exercising {perm}",
               [("METHOD",), ("SERVICE",), ("LOG",), ("NAME",), ("REQUIRED FIELDS (a real event carries)",)],
               caption="LOG: admin = always on · data = off unless enabled · NAME: verified = seen in real logs")
    for m in ms:
        info = cat.info(m)
        log = "data" if cat.is_data_access(m) else "admin"
        if s.account.logged(m):
            log += " ✓"
        req = ", ".join(f.split("labels[")[-1].rstrip("]") for f in cat.required_fields(m)) or "—"
        _add(t, m, cat.service_of(m), log, "verified" if cat.verified(m) else "unverified", req)
    console.print(t)
    console.print(f"[muted]principals holding it: {', '.join(s.account.principals_with(perm)) or '(none in this account)'}[/muted]")


def export(s: Session, args: list[str]) -> None:
    """Write the last run's witness events as Cloud Audit Log JSON (a list of entries), so a
    blind spot can be replayed in the real SIEM."""
    import json

    from decnique.detections import to_audit_log

    rep = s.last_report
    if rep is None:
        console.print("[warn]nothing to export[/warn] — run blindspots / stealth / chains / check first")
        return
    if not args:
        console.print("[muted]usage:[/muted] export <file.json> [n]   (n = only the n-th finding)")
        return
    events: list[dict] = []
    for i, it in enumerate(rep.items, 1):
        if len(args) > 1 and str(i) != args[1]:
            continue
        for ev in ([it["event"]] if it.get("event") else []) + list(it.get("schedule") or []) + \
                  ([it["witness"]] if it.get("witness") else []):
            entry = to_audit_log(ev)
            entry["_decnique"] = {"finding": i, "label": it["label"], "verdict": it["verdict"], "verb": rep.verb}
            events.append(entry)
    if not events:
        console.print("[muted]the last run has no witness events[/muted]")
        return
    Path(args[0]).write_text(json.dumps(events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    console.print(f"[ok]{CHECK}[/ok] wrote [title]{len(events)}[/title] audit-log entr{'y' if len(events) == 1 else 'ies'} → [key]{args[0]}[/key]")


def suggest(s: Session, args: list[str]) -> None:
    """Propose DSL detections that close a permission's blind spot: one per unwatched kind of
    change (the rules' own tests the corpus does not cover), plus the coarse catch-all.  With
    `define`, the blocks are added to the session so `blindspots` / `check` can confirm."""
    if not s.need_lib() or not s.need_account():
        return
    from decnique.dsl import format as fmt
    from decnique.model.predicates import In, all_of
    from decnique.smt.coverage import CoverageContext, Gap, find_gap, probe_atoms

    define = "define" in args
    perms = [a for a in args if a != "define"]
    if not perms:
        console.print("[muted]usage:[/muted] suggest <permission> [permission …] [define]")
        return
    lib, account = s.lib, s.account
    ctx = CoverageContext(lib)
    blocks: list[str] = []
    for p in perms:
        logged = sorted(m for m in account.catalog.methods_for(p) if account.logged(m))
        if not logged:
            console.print(f"[muted]{p}: no logged method — a rule cannot help; turn logging on[/muted]")
            continue
        res = find_gap(p, lib, account, ctx=ctx)
        if not isinstance(res, Gap):
            console.print(f"[safe]{p}: {res.reason} — nothing to close[/safe]")
            continue
        slug = "".join(c if c.isalnum() else "_" for c in p)
        methods = In(field=(None, "method"), values=tuple(logged))
        n = 0
        for v in probe_atoms(p, lib, account, ctx=ctx):
            if not isinstance(v.result, Gap):
                continue
            n += 1
            pred = all_of([methods, *(a.pred() for a in v.atoms)])
            blocks.append(f"detection close_{slug}_{n} {{\n  meta {{ note = \"suggested by decnique: unwatched change on {p}\" }}\n"
                          f"  event {fmt.pred(pred)}\n}}")
        blocks.append(f"detection watch_{slug} {{\n  meta {{ note = \"suggested by decnique: every logged use of {p}\" }}\n"
                      f"  event {fmt.pred(methods)}\n}}")
        console.print(f"[title]{p}[/title]: {n} unwatched change(s) → {n} targeted rule(s) + 1 catch-all")
    if not blocks:
        return
    text = "\n\n".join(blocks)
    console.print(Panel(text, title="suggested detections (DSL) — paste, edit, or `suggest … define`", border_style="accent"))
    if define:
        s.define(text, "<suggest>")
        console.print("[muted]defined into the session — run `blindspots <permission>` or a `check` to confirm[/muted]")


def report_diff(s: Session, a: str, b: str) -> None:
    """What changed between two saved runs of the same verb: findings that appeared, closed,
    or changed verdict — the before/after of a rule edit or a corpus update."""
    from .report import load

    da, db = load(_report_path(s, a)), load(_report_path(s, b))
    if da["verb"] != db["verb"]:
        console.print(f"[warn]different verbs[/warn] ({da['verb']} vs {db['verb']}) — comparing anyway")
    ia = {it["label"]: it for it in da["items"]}
    ib = {it["label"]: it for it in db["items"]}
    t = _table(f"{da['verb']}: {Path(a).name} → {Path(b).name}", [("FINDING",), ("BEFORE",), ("AFTER",), ("CHANGE",)])
    changed = 0
    for label in sorted(set(ia) | set(ib)):
        va, vb = ia.get(label, {}).get("verdict", "—"), ib.get(label, {}).get("verdict", "—")
        if va == vb:
            continue
        changed += 1
        word = "new" if label not in ia else "gone" if label not in ib else "changed"
        _add(t, label, va, vb, word)
    if changed:
        console.print(t)
    console.print(f"[title]diff[/title]  {changed} finding(s) changed · summary before {da.get('summary')} · after {db.get('summary')}")


def _report_path(s: Session, name: str) -> Path:
    p = Path(name)
    if not p.exists():
        p = Path(s.settings.get("report.dir")) / name
    return p


def _payload(ev: dict) -> str:
    """The parts of a schedule event a red teamer acts on: the binding-delta payload and any
    fields the technique pinned (principal, caller_ip, …), skipping the derived boilerplate."""
    bits = []
    for k, v in (ev.get("udm") or {}).items():
        key = k.split("ser_binding_deltas_")[-1].rstrip("]") if "ser_binding_deltas_" in k else k
        bits.append(f"{key}={v}")
    for k in ("principal", "caller_ip", "user_agent"):
        if ev.get(k):
            bits.append(f"{k}={ev[k]}")
    return ", ".join(bits) or "—"


def _service_summary(rep) -> None:  # type: ignore[no-untyped-def]
    """Verdict counts per GCP service (the permission's first segment) — the shape of the
    account's exposure at a glance when thousands of permissions were probed."""
    from collections import defaultdict

    rows: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for it in rep.items:
        rows[it["label"].split(".")[0]][it["verdict"]] += 1
    t = _table("by service", [("SERVICE",), ("GAPS", "right"), ("COVERED", "right"), ("UNLOGGED", "right"),
                              ("OTHER", "right")],
               caption="UNLOGGED = Data Access logging off for every method · OTHER = unreachable / inconclusive")
    for svc, c in sorted(rows.items(), key=lambda kv: (-kv[1]["gap"], kv[0])):
        other = sum(n for k, n in c.items() if k not in ("gap", "all_covered", "unlogged"))
        _add(t, svc, str(c["gap"]), str(c["all_covered"]), str(c["unlogged"]), str(other))
    console.print(t)


def stealth(s: Session, ident: str | None) -> None:
    if not s.need_lib() or not s.need_account():
        return
    from decnique.smt.stealth import Evasive, feasible, stealth_feasible

    lib, account = s.lib, s.account
    cands = [c for c in lib.bundle.candidates if not ident or c.id == ident]
    if not cands:
        console.print("[muted]no candidates to evaluate" + (f" for {ident!r}" if ident else "") + "[/muted]")
        return

    with s.report("stealth", [ident] if ident else []) as rep:
        _stealth(lib, account, cands, rep)


def _stealth(lib, account, cands, rep) -> None:  # type: ignore[no-untyped-def]
    from decnique.smt.stealth import Evasive, feasible, stealth_feasible

    r = Reasoner()
    r.header(
        "stealth",
        formula="∃ τ :  Footprint(τ) ∧ Reach ∧ Log ∧ ¬( ⋁ Fires(R, τ) )",
        subtitle="can a technique be run so that no rule fires? each evasive schedule is replayed "
                 "through the concrete oracle before it is believed",
    )

    rows = []
    evasive = 0
    for c in cands:
        r.section(c.id)
        req = [rq.permission for rq in c.required]
        r.note(f"requires: {', '.join(req) or '—'}")
        principals = feasible(c, account)
        if not principals:
            missing = [rq.permission for rq in c.required if not account.reachable(rq.permission)]
            r.no(f"not feasible — actor cannot obtain: {', '.join(missing) or '(no single principal holds all)'}")
            rows.append((c.id, ("not_feasible", "muted"), ", ".join(missing) or "—", ("—", "muted")))
            rep.add(c.id, "not_feasible", "actor cannot obtain: " + (", ".join(missing) or "no single principal holds all"))
            r.blank()
            continue
        r.ok(f"feasible as {principals[0]}")
        r.math("proposing a schedule that evades every exactly-encoded rate rule, refuting each with the oracle")
        with r.thinking("SMT: solving for an evasive schedule (≤64 refinements)…"):
            res = stealth_feasible(c, lib, account)
        if isinstance(res, Evasive):
            with r.thinking(f"replay: realizing the footprint and firing all {len(lib.detections)} rules…"):
                realized = matches_footprint(c.footprint, res.schedule, ref_lists=lib.ref_lists) is True
                verdicts = {d.id: fires(d.spec, res.schedule, ref_lists=lib.ref_lists) for d in lib.detections}
            n_fire = sum(v is True for v in verdicts.values())
            n_unk = sum(v is None for v in verdicts.values())
            r.note(f"schedule: {len(res.schedule)} event(s), method {res.schedule[0].get('method', '—')}")
            r.replay(f"replay: footprint {'realized' if realized else 'NOT realized'}, "
                     f"{n_fire}/{len(lib.detections)} fire, {n_unk} unknown → "
                     f"{'sound' if realized and n_fire == 0 else 'REJECTED'}",
                     sound=(realized and n_fire == 0))
            if n_unk:
                r.note(unknown_summary(lib, [rid for rid, v in verdicts.items() if v is None]))
            tag = "approximate" if res.approximate else "exact"
            if res.unlogged:
                r.no(f"not audit-logged by this account: {', '.join(res.unlogged)} — "
                       "no rule can see these steps (a logging gap, not a rule gap)")
            r.verdict_gap(f"EVASIVE ({tag}) — {len(res.schedule)} event(s) as {res.principal} evade every rule")
            rows.append((c.id, ("evasive", "gap"), f"{len(res.schedule)} events as {res.principal}"
                         + (" (unlogged step)" if res.unlogged else ""), approx_word(res.approximate)))
            rep.add(c.id, "evasive", f"{len(res.schedule)} event(s) as {res.principal} evade every rule",
                    approximate=res.approximate, principal=res.principal, schedule=list(res.schedule),
                    unlogged=list(res.unlogged))
            evasive += 1
        elif res.verdict == "always_detected":
            caught = ", ".join(_title(lib, rid) for rid in res.caught_by)
            r.verdict_safe("always detected — UNSAT: every schedule trips a rule (proof over the encoded class)"
                           + (f"\n        always caught by: {caught}" if caught else ""))
            rows.append((c.id, ("always_detected", "safe"), caught or "—", ("—", "muted")))
            rep.add(c.id, "always_detected", "every schedule trips a rule (UNSAT proof)", caught_by=list(res.caught_by))
        else:
            r.verdict_muted("exhausted — refinement bound reached without a schedule")
            rows.append((c.id, ("exhausted", "muted"), "—", ("—", "muted")))
            rep.add(c.id, "exhausted", "refinement bound reached without a schedule")
        r.blank()

    rep.summary = {"evasive": evasive, "techniques": len(cands)}
    console.print(f"[title]result[/title]  [gap]{evasive}[/gap] of {len(cands)} technique(s) evade every rule")
    t = _table("stealth verdicts", [("TECHNIQUE",), ("VERDICT",), ("DETAIL",), ("STATUS",)],
               caption="evasive = a defender blind spot · always_detected = proven caught · "
                       "not_feasible = actor lacks the permissions")
    for row in rows:
        _add(t, *row)
    console.print(t)


def chains(s: Session, args: list[str]) -> None:
    if not s.need_lib() or not s.need_account():
        return
    from decnique.answers import techniques_for

    lib, account = s.lib, s.account
    attack = dict(s.account_doc.get("attack", {}))
    # flags let the red teamer set the plan without touching the defender's account file
    rest: list[str] = []
    it = iter(args)
    for a in it:
        if a in ("--from", "--goal"):
            attack["principal" if a == "--from" else "goal"] = next(it, "")
        elif a == "--start":
            attack["initial_state"] = [x for x in next(it, "").split(",") if x]
        else:
            rest.append(a)
    if rest:
        attack["goal"] = rest[0]
    if "goal" not in attack:
        console.print(
            "[warn]chains needs a goal permission[/warn] — `chains <permission>`, or `--goal`, "
            "or a `goal` in the account's `attack` block.\n"
            "  optional: `--from <principal>` `--start p1,p2` (default: the account's most "
            "capable principal and what they already hold)."
        )
        return
    if not techniques_for(lib, account):
        console.print("[warn]no techniques with an effect[/warn] — a candidate needs a `gains { … }` "
                      "clause (or an `effects` table in the account) to advance a chain.")
        return

    with s.report("chains", args) as rep:
        _chains(lib, account, attack, rep)


def _chains(lib, account, attack, report) -> None:  # type: ignore[no-untyped-def]
    from decnique.graph.search import price_transitions
    from decnique.answers import chains_report, techniques_for

    r = Reasoner()
    r.header(
        "chains",
        formula="BFS over reachable states :  every hop ∃ an evasive schedule (M3), Reach grows per hop",
        subtitle=f"from {attack['principal']} to the goal permission; the search is exhaustive over the "
                 f"finite reachable state space",
    )
    from decnique.answers import _start

    principal, initial = _start(account, attack)
    r.section("start")
    r.note(f"principal: {principal}")
    r.note(f"initial permissions: {', '.join(sorted(initial)) or '(none)'}")
    r.note(f"goal: {attack['goal']}")

    # Detection-pricing at the initial state: which techniques are stealthy from here?
    techs = techniques_for(lib, account, attack.get("effects", {}))
    if techs:
        r.section("pricing the initial state", "which moves are stealthy right now?")
        with r.thinking("evaluating each applicable technique's detection price…"):
            edges = price_transitions(techs, lib, account, principal, initial)
        for e in edges:
            (r.ok if e.stealthy else r.no)(
                f"{e.technique}: {'stealthy' if e.stealthy else e.verdict}"
            )
        if not edges:
            r.note("no technique applies at the initial state")

    with r.thinking("BFS: expanding states, stealth-checking each hop…"):
        rep = chains_report(lib, account, attack)

    if not rep["found"]:
        r.blank()
        r.verdict_safe(f"no stealthy path to {rep['goal']}")
        r.note(f"proven by exhausting {rep['states_explored']} reachable state(s) ({rep['reason']})")
        console.print(f"[safe]result[/safe]  no stealthy escalation to {rep['goal']}")
        report.summary = {"found": False, "goal": rep["goal"], "states_explored": rep["states_explored"],
                          "reason": rep["reason"], "principal": principal}
        return

    # Found: narrate each hop, then replay the whole path as one trace (hops laid end to end
    # with the delays the search chose) — that is what a correlation rule would see.
    r.blank()
    whole: list[dict] = []
    for i, h in enumerate(rep["hops"]):
        r.section(f"hop {i + 1}: {h['technique']}")
        r.note(f"gains: {', '.join(h['gains']) or '—'}")
        sched = h.get("schedule", [])
        if h.get("delay"):
            r.note(f"waits {h['delay']} s after the previous hop (longer than every rule window)")
        start = max((int(e.get("time", 0)) for e in whole), default=0) + int(h.get("delay", 0))
        whole += [{**e, "time": int(e.get("time", 0)) + start} for e in sched]
    seen = [e for e in whole if account.logged(str(e.get("method", "")))]
    with r.thinking(f"replay: firing all {len(lib.detections)} rules on the whole path ({len(seen)} logged event(s))…"):
        verdicts = {d.id: fires(d.spec, seen, ref_lists=lib.ref_lists) for d in lib.detections}
    n_fire = sum(v is True for v in verdicts.values())
    n_unk = sum(v is None for v in verdicts.values())
    r.replay(f"replay of the whole path: {n_fire}/{len(lib.detections)} fire, {n_unk} unknown → "
             f"{'sound' if n_fire == 0 else 'REJECTED'}", sound=(n_fire == 0))

    tag = "approximate" if rep["tag"] == "approximate" else "stealthy"
    report.summary = {"found": True, "goal": rep["goal"], "hops": len(rep["hops"]), "tag": rep["tag"],
                      "principal": principal}
    for i, h in enumerate(rep["hops"]):
        report.add(f"hop {i + 1}: {h['technique']}", "stealthy", "gains " + (", ".join(h["gains"]) or "—"),
                   gains=list(h["gains"]), schedule=list(h.get("schedule", [])), delay=h.get("delay", 0))
    r.blank()
    r.verdict_gap(f"{tag.upper()} PATH to {rep['goal']} — {len(rep['hops'])} hop(s)")
    # the executable plan: one row per event, absolute time, method, principal, payload
    t = _table(f"stealthy escalation to {rep['goal']} — as {principal}",
               [("t (s)", "right"), ("HOP",), ("METHOD",), ("PAYLOAD / notes",)])
    clock = 0
    for i, h in enumerate(rep["hops"], 1):
        clock += int(h.get("delay", 0))
        base = clock
        for ev in h.get("schedule", []):
            _add(t, str(base + int(ev.get("time", 0))), f"{i} {h['technique']}",
                 str(ev.get("method", "—")), _payload(ev))
        clock = base + max((int(e.get("time", 0)) for e in h.get("schedule", [])), default=0)
    console.print(t)
    r.note("export the plan as replayable audit-log JSON with `export <file.json>`")


# --- checks: the DSL's own questions ------------------------------------------------------------

_CHECK_QUESTION = {
    "coverage": "is every reachable+logged event for the permission(s) observed by some rule?",
    "candidate": "is the technique caught however it is scheduled?",
    "compare": "do the two rules observe the same events?",
    "dead_rules": "can every rule fire on some reachable+logged event?",
    "redundant_rules": "does every rule observe an event no other rule observes?",
    "boundary": "can an event matching `event` (not `allowed`) happen unseen?",
    "require_coverage": "is the technique's step (method + payload) watched however it is done?",
    "attempt_coverage": "is a DENIED attempt at the technique's step watched?",
    "public_access": "can allUsers / allAuthenticatedUsers use the permission unseen?",
}


def _check_params(c) -> str:  # type: ignore[no-untyped-def]
    from decnique.dsl.format import pred

    parts = []
    for k, v in c.params.items():
        if k in {"event", "allowed"}:
            parts.append(f"{k} {pred(v)}")
        elif isinstance(v, tuple):
            parts.append(f"{k} [{', '.join(v)}]")
        else:
            parts.append(f"{k} {v}")
    return "  ".join(parts) or "—"


def checks(s: Session) -> None:
    if not s.need_lib():
        return
    from decnique.checks import IMPLEMENTED

    items = s.lib.bundle.checks
    if not items:
        console.print("[muted]no checks loaded — type one at the prompt, e.g. "
                      "[key]check c { type coverage permission iam.serviceAccountKeys.create }[/key][/muted]")
        return
    t = _table("checks", [("ID",), ("TYPE",), ("OPTIONS",), ("QUESTION",)],
               caption="run with: check [id…]  ·  every answer is pass / fail / unknown")
    for c in items:
        q = _CHECK_QUESTION.get(c.type, "no engine yet — answers unknown")
        _add(t, c.id, (c.type, "key" if c.type in IMPLEMENTED else "muted"), _check_params(c), q)
    console.print(t)


def check(s: Session, args: list[str]) -> None:
    """Run check blocks: all loaded ones, the named ones, or those in the given .decn files."""
    from pathlib import Path

    from decnique.checks import CheckError, run_checks

    if not s.need_lib() and not any(Path(a).is_file() for a in args):
        return
    wanted: list = []
    for a in args:
        if Path(a).is_file():  # a file: define its items, then run the checks it holds
            wanted.extend(s.define(Path(a).read_text(encoding="utf-8"), a).checks)
        else:
            hit = [c for c in (s.lib.bundle.checks if s.lib else ()) if c.id == a]
            if not hit:
                console.print(f"[warn]no check named {a!r}[/warn] — see [key]checks[/key]")
                return
            wanted.extend(hit)
    if not args:
        wanted = list(s.lib.bundle.checks) if s.lib else []
    if not wanted:
        console.print("[muted]no checks to run — type one at the prompt or pass a .decn file[/muted]")
        return

    lib, account = s.lib, s.account
    with s.report("check", args) as rep:
        _check(lib, account, wanted, rep)


def _check(lib, account, wanted, rep) -> None:  # type: ignore[no-untyped-def]
    from decnique.checks import CheckError, run_checks

    r = Reasoner()
    r.header(
        "check",
        formula="each block asks one question; a witness is replayed before it is believed",
        subtitle=f"{len(wanted)} check(s) · {len(lib.detections)} rule(s) · "
                 f"account {account.name if account else '— (none: only `compare` can run)'}",
    )
    rows = []
    for c in wanted:
        r.section(c.id, f"{c.type}: {_CHECK_QUESTION.get(c.type, 'no engine yet')}")
        r.note(_check_params(c))
        try:
            with r.thinking("solving…"):
                res = run_checks([c], lib, account)[0]
        except CheckError as e:
            r.verdict_muted(f"cannot run: {e}")
            rows.append((c.id, c.type, ("error", "muted"), str(e)))
            rep.add(c.id, "error", str(e), type=c.type)
            r.blank()
            continue
        for row in res.rows:
            line = f"{row.label}: {row.note}"
            if row.verdict == "pass":
                r.ok(line)
            elif row.verdict == "fail":
                r.no(line)
                w = row.witness
                if isinstance(w, dict):
                    r.note(f"witness: {event_sentence(w)}")
                    fired = sum(fires(d.spec, [w], ref_lists=lib.ref_lists) is True for d in lib.detections)
                    r.replay(f"replay: {fired}/{len(lib.detections)} rules fire → {'sound' if not fired else 'REJECTED'}",
                             sound=not fired)
                elif isinstance(w, tuple):
                    r.note(f"witness: {len(w)} event(s), first {event_brief(w[0])}")
            else:
                r.note(line)
        tag = " (~approx)" if res.approximate else ""
        if res.verdict == "pass":
            r.verdict_safe(f"PASS{tag} — {res.detail}")
        elif res.verdict == "fail":
            r.verdict_gap(f"FAIL{tag} — {res.detail}")
        else:
            r.verdict_muted(f"UNKNOWN{tag} — {res.detail}")
        rows.append((c.id, c.type, (res.verdict, {"pass": "safe", "fail": "gap"}.get(res.verdict, "muted")),
                     res.detail))
        rep.add(c.id, res.verdict, res.detail, type=c.type, approximate=res.approximate,
                rows=[{"label": x.label, "verdict": x.verdict, "note": x.note, "witness": x.witness} for x in res.rows])
        r.blank()
    n_fail = sum(1 for _, _, v, _ in rows if v[0] == "fail")
    n_pass = sum(1 for _, _, v, _ in rows if v[0] == "pass")
    rep.summary = {"pass": n_pass, "fail": n_fail, "unknown": len(rows) - n_pass - n_fail, "checks": len(rows)}
    console.print(f"[title]result[/title]  [safe]{n_pass} pass[/safe] · [gap]{n_fail} fail[/gap] · "
                  f"{len(rows) - n_pass - n_fail} unknown")
    t = _table("check verdicts", [("CHECK",), ("TYPE",), ("VERDICT",), ("DETAIL",)])
    for row in rows:
        _add(t, *row)
    console.print(t)


# --- saved reports ----------------------------------------------------------------------------


def reports(s: Session) -> None:
    from .report import list_reports, load

    d = s.settings.get("report.dir")
    files = list_reports(d)
    if not files:
        console.print(f"[muted]no reports in {d}/ — turn saving on with [key]config report.save on[/key][/muted]")
        return
    t = _table(f"reports in {d}/", [("FILE",), ("VERB",), ("WHEN",), ("SUMMARY",)],
               caption="reopen one with: report <file>")
    for p in files:
        try:
            doc = load(p)
            summ = ", ".join(f"{k} {v}" for k, v in doc.get("summary", {}).items())
            _add(t, p.name, doc.get("verb", "?"), doc.get("started", "?"), summ or "—")
        except (OSError, ValueError):
            _add(t, p.name, ("unreadable", "muted"), "—", "—")
    console.print(t)


def report(s: Session, file: str | None, *more: str) -> None:
    if file == "diff":
        if len(more) != 2:
            console.print("[muted]usage:[/muted] report diff <a> <b>")
            return
        report_diff(s, more[0], more[1])
        return
    _report_one(s, file)


def _report_one(s: Session, file: str | None) -> None:
    """Re-render a saved run: what was loaded, the summary, and every finding."""
    from pathlib import Path

    from .report import list_reports, load

    if not file:
        console.print("[muted]usage:[/muted] report <file>   (see [key]reports[/key])")
        return
    path = Path(file)
    if not path.is_file():  # allow a bare name from the reports folder
        path = Path(s.settings.get("report.dir")) / file
    doc = load(path)
    verb, args = doc.get("verb", "?"), " ".join(doc.get("args", []))
    console.print(Panel(Text(f"{verb} {args}".strip(), style="brand"), title=Text(f"report · {doc.get('started', '')}", style="brand"),
                        title_align="left", border_style="rule", padding=(0, 1)))
    lib = doc.get("library", {})
    if lib:
        console.print("[muted]loaded:[/muted] " + " · ".join(
            f"{k} {', '.join(map(str, v)) if isinstance(v, list) else v}" for k, v in lib.items() if v))
    if doc.get("summary"):
        console.print("[title]summary[/title]  " + " · ".join(f"{k} {v}" for k, v in doc["summary"].items()))
    items = doc.get("items", [])
    if items:
        t = _table("findings", [("#", "right"), ("LABEL",), ("VERDICT",), ("DETAIL",)])
        style = {"gap": "gap", "evasive": "gap", "fail": "gap", "stealthy": "gap", "pass": "safe",
                 "always_detected": "safe", "all_covered": "safe"}
        for i, it in enumerate(items, 1):
            v = str(it.get("verdict", ""))
            _add(t, str(i), it.get("label", ""), (v, style.get(v, "muted")), it.get("detail", ""))
        console.print(t)
        for it in items:  # the concrete witnesses, one line each
            ev = it.get("event")
            if isinstance(ev, dict):
                console.print(f"    [muted]{it.get('label')}:[/muted] {event_sentence(ev)}")
            sched = it.get("schedule")
            if isinstance(sched, list) and sched:
                console.print(f"    [muted]{it.get('label')}:[/muted] {len(sched)} event(s), first {event_brief(sched[0])}")
    console.print(f"[muted]transcript: {len(doc.get('transcript', '') or '')} chars — open the file to read it[/muted]")

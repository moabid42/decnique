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
    shown = [d for d in s.lib.detections if not filt or filt in d.id]
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
            _print_source("detection", d.id, fmt.detection(d), approximate=d.approximate)
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


def _print_source(kind: str, ident: str, text: str, *, approximate: bool = False) -> None:
    tag = Text()
    tag.append(f"{kind}  ", style="muted")
    tag.append(ident, style="brand")
    if approximate:
        tag.append("   ~approx", style="approx")
    console.print(
        Panel(
            Text(text),
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
            if u.raw and u.label not in seen:
                rows.append((u.label, u.raw[:80], _UNTRANSLATED_WHY.get(u.label, "unsupported construct")))
                seen.add(u.label)
    return rows


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
    covered = unreachable = unlogged = 0

    for p in permissions:
        r.section(p)
        if not account.reachable(p):
            r.no("unreachable — no principal in this account can exercise it")
            unreachable += 1
            r.blank()
            continue
        principals = account.principals_with(p)
        r.ok(f"Reach: exercisable by {', '.join(principals)}")
        all_methods = sorted(account.catalog.methods_for(p))
        logged = [m for m in all_methods if account.logged(m)]
        if not logged:
            r.no(f"Log: none of {len(all_methods)} method(s) is audit-logged → invisible regardless of rules")
            unlogged += 1
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
                r.verdict_muted("inconclusive — refinement bound exhausted")
                covered += 1
            else:
                r.verdict_muted(res.reason)
                covered += 1
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
        for c in res.caveats:
            r.note(f"caveat: {c}")
        tag = "approximate" if res.approximate else "exact"
        # The witness is only the *simplest* unobserved event.  Explain the whole hole, the
        # way the user configured (`config blindspots.explain rules|formula|both`).
        logged = [m for m in account.catalog.methods_for(p) if account.logged(m)]
        naming = rules_naming(lib, logged)
        if explain == "words":
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
        if explain in ("rules", "both"):
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
        if explain in ("formula", "both"):
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
        verdicts = verdicts if explain in ("rules", "both", "words") else ()
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
        r.blank()

    console.print(
        f"[title]result[/title]  [gap]{len(gaps)} gaps[/gap] · "
        f"[safe]{covered} covered[/safe] · {unreachable} unreachable · {unlogged} unlogged"
    )
    if gaps:
        t = _table("blind spots", [("PERMISSION",), ("METHOD",), ("PRINCIPAL",), ("STATUS",)])
        for g in gaps:
            _add(t, g["permission"], g["event"].get("method", "—"), g["event"].get("principal", "—"),
                 approx_word(g["approximate"]))
        console.print(t)
    else:
        console.print("[safe]no blind spots for the probed permissions[/safe]")


def stealth(s: Session, ident: str | None) -> None:
    if not s.need_lib() or not s.need_account():
        return
    from decnique.smt.stealth import Evasive, feasible, stealth_feasible

    lib, account = s.lib, s.account
    cands = [c for c in lib.bundle.candidates if not ident or c.id == ident]
    if not cands:
        console.print("[muted]no candidates to evaluate" + (f" for {ident!r}" if ident else "") + "[/muted]")
        return

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
            tag = "approximate" if res.approximate else "exact"
            r.verdict_gap(f"EVASIVE ({tag}) — {len(res.schedule)} event(s) as {res.principal} evade every rule")
            rows.append((c.id, ("evasive", "gap"), f"{len(res.schedule)} events as {res.principal}",
                         approx_word(res.approximate)))
            evasive += 1
        elif res.verdict == "always_detected":
            r.verdict_safe("always detected — UNSAT: every schedule trips a rate rule (proof over the encoded class)")
            rows.append((c.id, ("always_detected", "safe"), "—", ("—", "muted")))
        else:
            r.verdict_muted("exhausted — refinement bound reached without a schedule")
            rows.append((c.id, ("exhausted", "muted"), "—", ("—", "muted")))
        r.blank()

    console.print(f"[title]result[/title]  [gap]{evasive}[/gap] of {len(cands)} technique(s) evade every rule")
    t = _table("stealth verdicts", [("TECHNIQUE",), ("VERDICT",), ("DETAIL",), ("STATUS",)],
               caption="evasive = a defender blind spot · always_detected = proven caught · "
                       "not_feasible = actor lacks the permissions")
    for row in rows:
        _add(t, *row)
    console.print(t)


def chains(s: Session, goal: str | None) -> None:
    if not s.need_lib() or not s.need_account():
        return
    from decnique.graph.search import price_transitions
    from decnique.graph.state import Technique
    from decnique.report import chains_report

    lib, account = s.lib, s.account
    attack = dict(s.account_doc.get("attack", {}))
    if goal:
        attack["goal"] = goal
    if "goal" not in attack or "principal" not in attack:
        console.print(
            "[warn]chains needs an `attack` block[/warn] in the account file "
            "(principal, initial_state, goal, effects) — or pass a goal permission."
        )
        return

    r = Reasoner()
    r.header(
        "chains",
        formula="BFS over reachable states :  every hop ∃ an evasive schedule (M3), Reach grows per hop",
        subtitle=f"from {attack['principal']} to the goal permission; the search is exhaustive over the "
                 f"finite reachable state space",
    )
    initial = frozenset(attack.get("initial_state", ()))
    r.section("start")
    r.note(f"principal: {attack['principal']}")
    r.note(f"initial permissions: {', '.join(sorted(initial)) or '(none)'}")
    r.note(f"goal: {attack['goal']}")

    # Detection-pricing at the initial state: which techniques are stealthy from here?
    by_id = {c.id: c for c in lib.bundle.candidates}
    effects = attack.get("effects", {})
    techs = [Technique(by_id[cid], gains=tuple(g)) for cid, g in effects.items() if cid in by_id]
    if techs:
        r.section("pricing the initial state", "which moves are stealthy right now?")
        with r.thinking("evaluating each applicable technique's detection price…"):
            edges = price_transitions(techs, lib, account, attack["principal"], initial)
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
        return

    # Found: narrate and replay-verify each hop.
    r.blank()
    for i, h in enumerate(rep["hops"]):
        r.section(f"hop {i + 1}: {h['technique']}")
        r.note(f"gains: {', '.join(h['gains']) or '—'}")
        sched = h.get("schedule", [])
        with r.thinking(f"replay: firing all {len(lib.detections)} rules on {len(sched)} event(s)…"):
            verdicts = {d.id: fires(d.spec, sched, ref_lists=lib.ref_lists) for d in lib.detections}
        n_fire = sum(v is True for v in verdicts.values())
        n_unk = sum(v is None for v in verdicts.values())
        r.replay(f"replay: {n_fire}/{len(lib.detections)} fire, {n_unk} unknown → "
                 f"{'sound' if n_fire == 0 else 'REJECTED'}", sound=(n_fire == 0))

    tag = "approximate" if rep["tag"] == "approximate" else "stealthy"
    r.blank()
    r.verdict_gap(f"{tag.upper()} PATH to {rep['goal']} — {len(rep['hops'])} hop(s)")
    t = _table(f"stealthy escalation to {rep['goal']}",
               [("#", "right"), ("TECHNIQUE",), ("GAINS (new permissions)",), ("EVENTS", "right")])
    for i, h in enumerate(rep["hops"]):
        _add(t, str(i + 1), h["technique"], ", ".join(h["gains"]) or "—", str(h["events"]))
    console.print(t)


# --- checks: the DSL's own questions ------------------------------------------------------------

_CHECK_QUESTION = {
    "coverage": "is every reachable+logged event for the permission(s) observed by some rule?",
    "candidate": "is the technique caught however it is scheduled?",
    "compare": "do the two rules observe the same events?",
    "dead_rules": "can every rule fire on some reachable+logged event?",
    "redundant_rules": "does every rule observe an event no other rule observes?",
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
        r.blank()
    n_fail = sum(1 for _, _, v, _ in rows if v[0] == "fail")
    n_pass = sum(1 for _, _, v, _ in rows if v[0] == "pass")
    console.print(f"[title]result[/title]  [safe]{n_pass} pass[/safe] · [gap]{n_fail} fail[/gap] · "
                  f"{len(rows) - n_pass - n_fail} unknown")
    t = _table("check verdicts", [("CHECK",), ("TYPE",), ("VERDICT",), ("DETAIL",)])
    for row in rows:
        _add(t, *row)
    console.print(t)

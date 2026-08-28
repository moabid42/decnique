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
from .theme import approx_word, console, tri_word

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
    console.print(f"[warn]no detection or candidate named {ident!r}[/warn]")


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


def blindspots(s: Session, perms: list[str]) -> None:
    if not s.need_lib() or not s.need_account():
        return
    from decnique.smt.coverage import CoverageContext, Gap, find_gap

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
        subtitle=f"probing {len(permissions)} permission(s) against {len(single)} single-event "
                 f"detection(s); every witness is replayed through the concrete oracle",
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
        r.note(f"witness: {event_brief(res.event)}")
        r.replay(f"replay: {n_fire}/{len(lib.detections)} rules fire, {n_unk} unknown → "
                 f"{'sound' if n_fire == 0 else 'REJECTED'}", sound=(n_fire == 0))
        for c in res.caveats:
            r.note(f"caveat: {c}")
        tag = "approximate" if res.approximate else "exact"
        r.verdict_gap(f"BLIND SPOT ({tag}) — {res.event.get('method', '—')} unobserved")
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

"""Small pure string renderers for spec fragments — windows, count conditions, footprints.

These summarise a piece of AST into a single readable cell.  They are deliberately lossy
(the full, exact form is always one `show <id>` away); their job is to make a table scannable.
"""

from __future__ import annotations

from decnique.model.trace import AggCmp, CAnd, CNot, COr, Count, CTrue


def window_str(spec) -> str:
    w = spec.window
    if w is None:
        return "—"
    return f"{w.seconds}s" if w.side == "around" else f"{w.seconds}s/{w.side}"


def cond_str(c) -> str:
    if isinstance(c, CTrue):
        return "always"
    if isinstance(c, Count):
        return f"#{c.var}{c.op}{c.n}"
    if isinstance(c, AggCmp):
        return f"{c.name}{c.op}{c.n}"
    if isinstance(c, CAnd):
        return " & ".join(cond_str(x) for x in c.children)
    if isinstance(c, COr):
        return " | ".join(cond_str(x) for x in c.children)
    if isinstance(c, CNot):
        return f"!({cond_str(c.child)})"
    return "?"


def footprint_str(fp) -> str:
    parts = []
    for s in fp.steps:
        tag = s.id + (f"×{s.repeat}" if s.repeat and s.repeat != 1 else "")
        extras = []
        if s.within_seconds is not None:
            extras.append(f"within {s.within_seconds}s")
        if s.distinct:
            extras.append("distinct " + ",".join(q[1] for q in s.distinct))
        if extras:
            tag += f" ({'; '.join(extras)})"
        parts.append(tag)
    return ", ".join(parts)


def event_brief(ev: dict, *, keys: tuple[str, ...] = ("method", "principal", "resource")) -> str:
    """A one-line ``k=v`` digest of a (decoded) event, most-telling fields first.

    Values like ``!0!`` are z3 model-completion placeholders for fields the solver left free;
    they carry no information for a reader, so they are dropped."""

    def informative(v) -> bool:
        return v not in (None, "") and not (isinstance(v, str) and v.startswith("!"))

    shown = [f"{k}={ev[k]}" for k in keys if informative(ev.get(k))]
    rest = [f"{k}={v}" for k, v in ev.items() if k not in keys and informative(v)]
    return "  ".join(shown + rest) or "(empty event)"

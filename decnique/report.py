"""The coverage engine's top-level answers (plan §4 "global definition of done").

Given rules (a :class:`~decnique.detections.DetectionLibrary`) and an
:class:`~decnique.env.model.Account`, produce three JSON-serialisable reports, each entry tagged
``exact`` or ``approximate`` with the labels that made it approximate:

* :func:`blindspots_report`  — per-permission reachable+logged events no rule observes (M2).
* :func:`stealth_report`     — per-technique stealth verdicts + evasive schedules (M3).
* :func:`chains_report`      — stealthy privilege-escalation paths (M4).

:func:`full_report` bundles all three plus reproducible counts.  This is what the CLI ``coverage``
subcommand and the ``run.py`` verbs both call, so the tool has one honest source of truth.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from decnique.detections import DetectionLibrary
from decnique.env.model import Account
from decnique.graph.search import NoStealthyPath, StealthyPath, search_stealth_path
from decnique.graph.state import Technique
from decnique.smt.coverage import Gap, NoGap, probe_permissions
from decnique.smt.stealth import Evasive, stealth_feasible


def _tag(approximate: bool) -> str:
    return "approximate" if approximate else "exact"


def blindspots_report(
    lib: DetectionLibrary,
    account: Account,
    permissions: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    rep = probe_permissions(lib, account, permissions)
    gaps = [
        {
            "permission": g.permission,
            "tag": _tag(g.approximate),
            "event": g.event,
            "unknown_rules": list(g.unknown_rules),
            "caveats": list(g.caveats),
        }
        for g in rep.gaps
    ]
    return {
        "summary": rep.summary(),
        "gaps": gaps,
        "covered": list(rep.covered),
        "unreachable": list(rep.unreachable),
        "unlogged": list(rep.unlogged),
    }


def stealth_report(lib: DetectionLibrary, account: Account) -> dict[str, Any]:
    techniques = []
    for c in lib.bundle.candidates:
        r = stealth_feasible(c, lib, account)
        entry: dict[str, Any] = {"candidate": c.id, "verdict": r.verdict}
        if isinstance(r, Evasive):
            entry["tag"] = _tag(r.approximate)
            entry["principal"] = r.principal
            entry["events"] = len(r.schedule)
            entry["schedule"] = list(r.schedule)
            entry["unknown_rules"] = list(r.unknown_rules)
            entry["unlogged"] = list(r.unlogged)
        techniques.append(entry)
    evasive = sum(1 for t in techniques if t["verdict"] == "evasive")
    return {
        "summary": {"techniques": len(techniques), "evasive": evasive},
        "techniques": techniques,
    }


def techniques_for(lib: DetectionLibrary, account: Account, effects: Mapping[str, Any] | None = None) -> list[Technique]:
    """Every candidate that declares an effect — from its own ``gains`` clause, or from the
    ``effects`` override.  A candidate with no gain cannot advance the search and is skipped."""
    effects = effects or {}
    out: list[Technique] = []
    for c in lib.bundle.candidates:
        gains = tuple(effects[c.id]) if c.id in effects else c.gains
        if gains:
            out.append(Technique(c, gains=gains))
    return out


def _start(account: Account, attack: Mapping[str, Any]) -> tuple[str, frozenset]:
    """Principal and initial permissions for the search.  Defaults come from the account: the
    principal is the one given (or, if none, the one holding the most permissions — the attacker
    is whoever is most capable), and the initial state is what that principal already holds."""
    principal = attack.get("principal")
    if principal is None:
        principal = max(account.bindings, key=lambda p: len(account.bindings[p]), default="attacker")
    if "initial_state" in attack:
        return principal, frozenset(attack["initial_state"])
    held = {g.permission for g in account.bindings.get(principal, ()) if "*" not in g.permission}
    return principal, frozenset(held)


def chains_report(
    lib: DetectionLibrary,
    account: Account,
    attack: Mapping[str, Any],
) -> dict[str, Any]:
    """``attack`` supplies the start/goal of the search; the effect of each technique comes
    from its own ``gains`` clause, or from an ``effects`` override table::

        {"principal": "attacker@x.com",       # optional: default = every principal, best first
         "initial_state": [...],              # optional: default = what `principal` already holds
         "goal": "resourcemanager.projects.setIamPolicy",
         "effects": {"create_key": [...]}}    # optional: overrides a candidate's `gains`
    """
    techniques = techniques_for(lib, account, attack.get("effects", {}))
    principal, initial = _start(account, attack)
    goal = attack["goal"]
    result = search_stealth_path(
        techniques, lib, account, principal, initial, goal,
        max_depth=attack.get("max_depth"),
    )
    
    if isinstance(result, StealthyPath):
        return {
            "goal": goal,
            "found": True,
            "tag": _tag(result.approximate),
            "hops": [
                {
                    "technique": h.technique,
                    "gains": sorted(set(h.to_state) - set(h.from_state)),
                    "events": len(h.schedule),
                    "schedule": list(h.schedule),
                    "unknown_rules": list(h.unknown_rules),
                    "delay": h.delay,
                }
                for h in result.hops
            ],
        }
    assert isinstance(result, NoStealthyPath)
    return {
        "goal": goal,
        "found": False,
        "reason": result.reason,
        "states_explored": result.states_explored,
    }


def full_report(
    lib: DetectionLibrary,
    account: Account,
    *,
    permissions: tuple[str, ...] | None = None,
    attack: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "account": account.name,
        "detections_loaded": len(lib.detections),
        "candidates_loaded": len(lib.bundle.candidates),
        "blindspots": blindspots_report(lib, account, permissions),
        "stealth": stealth_report(lib, account),
    }
    if attack is not None:
        out["chains"] = chains_report(lib, account, attack)
    return out

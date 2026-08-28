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
        techniques.append(entry)
    evasive = sum(1 for t in techniques if t["verdict"] == "evasive")
    return {
        "summary": {"techniques": len(techniques), "evasive": evasive},
        "techniques": techniques,
    }


def chains_report(
    lib: DetectionLibrary,
    account: Account,
    attack: Mapping[str, Any],
) -> dict[str, Any]:
    """``attack`` supplies the declared effect table and the start/goal of the search::

        {"principal": "attacker@x.com",
         "initial_state": ["iam.serviceAccountKeys.create"],
         "goal": "resourcemanager.projects.setIamPolicy",
         "effects": {"create_key": ["iam.serviceAccounts.getAccessToken"], ...}}
    """
    effects: Mapping[str, list[str]] = attack.get("effects", {})
    by_id = {c.id: c for c in lib.bundle.candidates}
    techniques = [
        Technique(by_id[cid], gains=tuple(gains))
        for cid, gains in effects.items()
        if cid in by_id
    ]
    principal = attack["principal"]
    initial = frozenset(attack.get("initial_state", ()))
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

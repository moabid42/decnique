"""AST <-> plain dicts (YAML / JSON) for tooling and golden tests (plan §5.10)."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any as AnyT

import yaml

from decnique.dsl import ast as A
from decnique.model import predicates as P
from decnique.model import trace as T

_PRED_TYPES = {
    c.__name__: c
    for c in (
        P.Cmp,
        P.Like,
        P.Regex,
        P.StrFn,
        P.In,
        P.InCidr,
        P.InList,
        P.Exists,
        P.Const,
        P.Unknown,
        P.Not,
        P.All,
        P.Any,
    )
}
_AGG_TYPES = {c.__name__: c for c in (T.AggCall, T.AggConst, T.AggRef, T.AggIf, T.AggBin)}
_COND_TYPES = {c.__name__: c for c in (T.Count, T.AggCmp, T.CAnd, T.COr, T.CNot, T.CTrue, T.CUnknown)}


def _qf(f: P.QField) -> list[str | None]:
    return [f[0], f[1]]


def _qf_in(v: AnyT) -> P.QField:
    return (v[0], v[1])


def pred_to_dict(p: P.Pred) -> dict[str, AnyT]:
    d: dict[str, AnyT] = {"kind": type(p).__name__}
    for f in dataclasses.fields(p):
        v = getattr(p, f.name)
        if f.name == "field":
            d[f.name] = _qf(v)
        elif f.name == "fields":
            d[f.name] = [_qf(x) for x in v]
        elif f.name == "child":
            d[f.name] = pred_to_dict(v)
        elif f.name == "children":
            d[f.name] = [pred_to_dict(c) for c in v]
        elif isinstance(v, tuple):
            d[f.name] = list(v)
        else:
            d[f.name] = v
    return d


def pred_from_dict(d: dict[str, AnyT]) -> P.Pred:
    cls = _PRED_TYPES[d["kind"]]
    kw: dict[str, AnyT] = {}
    for f in dataclasses.fields(cls):
        if f.name not in d:
            continue
        v = d[f.name]
        if f.name == "field":
            kw[f.name] = _qf_in(v)
        elif f.name == "fields":
            kw[f.name] = tuple(_qf_in(x) for x in v)
        elif f.name == "child":
            kw[f.name] = pred_from_dict(v)
        elif f.name == "children":
            kw[f.name] = tuple(pred_from_dict(c) for c in v)
        elif isinstance(v, list):
            kw[f.name] = tuple(v)
        else:
            kw[f.name] = v
    return cls(**kw)


def agg_to_dict(a: T.AggExpr) -> dict[str, AnyT]:
    if isinstance(a, T.AggCall):
        return {"kind": "AggCall", "fn": a.fn, "arg": _qf(a.arg) if a.arg else None}
    if isinstance(a, T.AggConst):
        return {"kind": "AggConst", "value": a.value}
    if isinstance(a, T.AggRef):
        return {"kind": "AggRef", "name": a.name}
    if isinstance(a, T.AggIf):
        return {
            "kind": "AggIf",
            "cond": pred_to_dict(a.cond),
            "then": agg_to_dict(a.then),
            "else": agg_to_dict(a.else_),
        }
    return {
        "kind": "AggBin",
        "op": a.op,
        "left": agg_to_dict(a.left),
        "right": agg_to_dict(a.right),
    }


def agg_from_dict(d: dict[str, AnyT]) -> T.AggExpr:
    k = d["kind"]
    if k == "AggCall":
        return T.AggCall(d["fn"], _qf_in(d["arg"]) if d.get("arg") else None)
    if k == "AggConst":
        return T.AggConst(int(d["value"]))
    if k == "AggRef":
        return T.AggRef(d["name"])
    if k == "AggIf":
        return T.AggIf(
            pred_from_dict(d["cond"]), agg_from_dict(d["then"]), agg_from_dict(d["else"])
        )
    return T.AggBin(d["op"], agg_from_dict(d["left"]), agg_from_dict(d["right"]))


def cond_to_dict(c: T.CondExpr) -> dict[str, AnyT]:
    if isinstance(c, T.Count):
        return {"kind": "Count", "var": c.var, "op": c.op, "n": c.n}
    if isinstance(c, T.AggCmp):
        return {"kind": "AggCmp", "name": c.name, "op": c.op, "n": c.n}
    if isinstance(c, T.CNot):
        return {"kind": "CNot", "child": cond_to_dict(c.child)}
    if isinstance(c, T.CAnd | T.COr):
        return {"kind": type(c).__name__, "children": [cond_to_dict(x) for x in c.children]}
    if isinstance(c, T.CUnknown):
        return {"kind": "CUnknown", "label": c.label}
    return {"kind": "CTrue"}


def cond_from_dict(d: dict[str, AnyT]) -> T.CondExpr:
    k = d["kind"]
    if k == "Count":
        return T.Count(d["var"], d["op"], int(d["n"]))
    if k == "AggCmp":
        return T.AggCmp(d["name"], d["op"], int(d["n"]))
    if k == "CNot":
        return T.CNot(cond_from_dict(d["child"]))
    if k in {"CAnd", "COr"}:
        cls = T.CAnd if k == "CAnd" else T.COr
        return cls(tuple(cond_from_dict(x) for x in d["children"]))
    if k == "CUnknown":
        return T.CUnknown(str(d["label"]))
    return T.CTrue()


def spec_to_dict(s: T.TraceSpec) -> dict[str, AnyT]:
    return {
        "events": [{"name": e.name, "pred": pred_to_dict(e.pred)} for e in s.events],
        "joins": [[_qf(j.left), _qf(j.right)] for j in s.joins],
        "group_by": [_qf(q) for q in s.group_by],
        "window": {"seconds": s.window.seconds, "anchor": s.window.anchor, "side": s.window.side}
        if s.window
        else None,
        "order": list(s.order),
        "aggregates": [{"name": n, "expr": agg_to_dict(a)} for n, a in s.aggregates],
        "condition": cond_to_dict(s.condition),
        "options": {
            "allow_zero_values": s.options.allow_zero_values,
            "extra": dict(s.options.extra),
        },
    }


def spec_from_dict(d: dict[str, AnyT]) -> T.TraceSpec:
    w = d.get("window")
    opts = d.get("options") or {}
    return T.TraceSpec(
        events=tuple(T.EventVar(e["name"], pred_from_dict(e["pred"])) for e in d["events"]),
        joins=tuple(T.Join(_qf_in(a), _qf_in(b)) for a, b in d.get("joins", [])),
        group_by=tuple(_qf_in(q) for q in d.get("group_by", [])),
        window=T.Window(int(w["seconds"]), w.get("anchor"), w.get("side", "around")) if w else None,
        order=tuple(d.get("order", [])),
        aggregates=tuple((a["name"], agg_from_dict(a["expr"])) for a in d.get("aggregates", [])),
        condition=cond_from_dict(d["condition"]) if "condition" in d else T.CTrue(),
        options=T.RuleOptions(
            bool(opts.get("allow_zero_values", False)),
            tuple(sorted((opts.get("extra") or {}).items())),
        ),
    )


def detection_to_dict(d: A.Detection) -> dict[str, AnyT]:
    out: dict[str, AnyT] = {
        "kind": "detection",
        "id": d.id,
        "meta": dict(d.meta),
        "spec": spec_to_dict(d.spec),
    }
    if d.source:
        out["source"] = dataclasses.asdict(d.source)
    return out


def detection_from_dict(d: dict[str, AnyT]) -> A.Detection:
    src = d.get("source")
    return A.Detection(
        id=d["id"],
        spec=spec_from_dict(d["spec"]),
        meta=dict(d.get("meta") or {}),
        source=A.Provenance(
            **{
                **src,
                "unsupported": tuple(src.get("unsupported", ())),
                "notes": tuple(src.get("notes", ())),
            }
        )
        if src
        else None,
    )


def candidate_to_dict(c: A.Candidate) -> dict[str, AnyT]:
    return {
        "kind": "candidate",
        "id": c.id,
        "meta": dict(c.meta),
        "actor": pred_to_dict(c.actor) if c.actor else None,
        "required": [
            {"permission": r.permission, "where": pred_to_dict(r.where) if r.where else None}
            for r in c.required
        ],
        "footprint": {
            "steps": [
                {
                    "id": s.id,
                    "method": s.method,
                    "repeat": s.repeat,
                    "within_seconds": s.within_seconds,
                    "distinct": [_qf(q) for q in s.distinct],
                    "where": pred_to_dict(s.where) if s.where else None,
                }
                for s in c.footprint.steps
            ],
            "order": list(c.footprint.order),
            "span_seconds": c.footprint.span_seconds,
        },
        "context": pred_to_dict(c.context) if c.context else None,
        "share": list(c.share),
    }


def candidate_from_dict(d: dict[str, AnyT]) -> A.Candidate:
    fp = d["footprint"]
    return A.Candidate(
        id=d["id"],
        required=tuple(
            A.Required(r["permission"], pred_from_dict(r["where"]) if r.get("where") else None)
            for r in d["required"]
        ),
        footprint=A.Footprint(
            steps=tuple(
                A.Step(
                    s["id"],
                    s["method"],
                    int(s.get("repeat", 1)),
                    s.get("within_seconds"),
                    tuple(_qf_in(q) for q in s.get("distinct", [])),
                    pred_from_dict(s["where"]) if s.get("where") else None,
                )
                for s in fp["steps"]
            ),
            order=tuple(fp.get("order", [])),
            span_seconds=fp.get("span_seconds"),
        ),
        meta=dict(d.get("meta") or {}),
        actor=pred_from_dict(d["actor"]) if d.get("actor") else None,
        context=pred_from_dict(d["context"]) if d.get("context") else None,
        share=tuple(d.get("share") or ("principal",)),
    )


def check_to_dict(c: A.Check) -> dict[str, AnyT]:
    params = {
        k: (
            pred_to_dict(v)
            if isinstance(v, P.LEAF_TYPES + (P.Exists, P.Const, P.Unknown, P.Not, P.All, P.Any))
            else list(v)
            if isinstance(v, tuple)
            else v
        )
        for k, v in c.params.items()
    }
    return {"kind": "check", "id": c.id, "type": c.type, "params": params}


def check_from_dict(d: dict[str, AnyT]) -> A.Check:
    params: dict[str, object] = {}
    for k, v in (d.get("params") or {}).items():
        if isinstance(v, dict) and "kind" in v:
            params[k] = pred_from_dict(v)
        elif isinstance(v, list):
            params[k] = tuple(v)
        else:
            params[k] = v
    return A.Check(d["id"], d["type"], params)


def ruleset_to_dict(r: A.Ruleset) -> dict[str, AnyT]:
    return {
        "kind": "ruleset",
        "id": r.id,
        "includes": list(r.includes),
        "disabled": sorted(r.disabled),
        "enabled": sorted(r.enabled),
    }


def ruleset_from_dict(d: dict[str, AnyT]) -> A.Ruleset:
    return A.Ruleset(
        d["id"],
        tuple(d.get("includes", [])),
        frozenset(d.get("disabled", [])),
        frozenset(d.get("enabled", [])),
    )


def bundle_to_dict(b: A.Bundle) -> dict[str, AnyT]:
    return {
        "detections": [detection_to_dict(d) for d in b.detections],
        "candidates": [candidate_to_dict(c) for c in b.candidates],
        "checks": [check_to_dict(c) for c in b.checks],
        "rulesets": [ruleset_to_dict(r) for r in b.rulesets],
        "issues": [dataclasses.asdict(i) for i in b.issues],
    }


def bundle_from_dict(d: dict[str, AnyT]) -> A.Bundle:
    return A.Bundle(
        detections=tuple(detection_from_dict(x) for x in d.get("detections", [])),
        candidates=tuple(candidate_from_dict(x) for x in d.get("candidates", [])),
        checks=tuple(check_from_dict(x) for x in d.get("checks", [])),
        rulesets=tuple(ruleset_from_dict(x) for x in d.get("rulesets", [])),
        issues=tuple(A.LoadIssue(**x) for x in d.get("issues", [])),
    )


def dump_yaml(b: A.Bundle) -> str:
    return yaml.safe_dump(bundle_to_dict(b), sort_keys=False, allow_unicode=True)


def dump_json(b: A.Bundle, indent: int | None = 2) -> str:
    return json.dumps(bundle_to_dict(b), indent=indent, ensure_ascii=False)


def load_yaml(text: str) -> A.Bundle:
    return bundle_from_dict(yaml.safe_load(text) or {})


def load_json(text: str) -> A.Bundle:
    return bundle_from_dict(json.loads(text))


def save(b: A.Bundle, path: Path) -> None:
    path = Path(path)
    path.write_text(dump_json(b) if path.suffix == ".json" else dump_yaml(b), encoding="utf-8")


def load(path: Path) -> A.Bundle:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return load_json(text) if path.suffix == ".json" else load_yaml(text)

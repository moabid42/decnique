"""Panther front-end: ``.yml`` metadata + ``.py`` detection logic -> DSL detections.

Panther's logic is arbitrary Python, so it cannot be lowered faithfully.  The
front-end recovers what is syntactically visible - method-name and permission
literals used with ``==``, ``in``, ``endswith``/``startswith`` next to
``methodName``/``permission`` - and conjoins an ``Unknown("panther:python_logic")``
atom, so the result is always *approximate* and never claims more than the rule
text shows.  ``Threshold`` becomes ``condition #e >= N`` with the dedup period as the
window; ``correlation_rule`` files lower to a single ``Unknown`` event.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any as AnyT

import yaml

from decnique.dsl.ast import Bundle, Detection, LoadIssue, Provenance
from decnique.model.predicates import Cmp, In, Pred, StrFn, Unknown, all_of, any_of
from decnique.model.trace import Count, EventVar, RuleOptions, TraceSpec, Window, single_event

_METHOD_CTX = re.compile(r"(?:methodName|method_name|METHOD|method)\b", re.I)
_STR = r"(?:\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|'([^'\\]*(?:\\.[^'\\]*)*)')"
_ENDSWITH = re.compile(r"\.endswith\(\s*" + _STR + r"\s*\)")
_STARTSWITH = re.compile(r"\.startswith\(\s*" + _STR + r"\s*\)")
_EQ = re.compile(r"(?:==|!=)\s*" + _STR)
_IN_SET = re.compile(r"\bin\s*[\[({]([^\])}]*)[\])}]", re.S)
_SET_DEF = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*[\[({]([^\])}]*)[\])}]", re.M | re.S)
_ANY_STR = re.compile(_STR)
_PERM_CTX = re.compile(r"permission\W{0,10}" + _STR, re.I)
_METHOD_LIKE = re.compile(r"^[A-Za-z][A-Za-z0-9_.*-]*\.[A-Za-z][A-Za-z0-9_*-]*$")


def is_panther_gcp(doc: dict[str, AnyT]) -> bool:
    logtypes = doc.get("LogTypes") or []
    return any(str(t).startswith("GCP.") for t in logtypes) or str(
        doc.get("RuleID", "")
    ).startswith("GCP.")


_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_panther_file(path: Path, *, gcp_only: bool = True, text: str | None = None) -> Bundle:
    path = Path(path)
    if text is None:
        text = path.read_text(encoding="utf-8")
    if gcp_only and "GCP." not in text:
        return Bundle()
    try:
        doc = yaml.load(text, Loader=_LOADER)
    except yaml.YAMLError as e:
        return Bundle(issues=(LoadIssue("error", str(path), f"panther yaml: {e}"),))
    if not isinstance(doc, dict) or doc.get("AnalysisType") not in {
        "rule",
        "correlation_rule",
        "scheduled_rule",
    }:
        return Bundle()
    if gcp_only and not is_panther_gcp(doc):
        return Bundle()
    py_text = None
    if doc.get("Filename"):
        py_path = path.with_name(str(doc["Filename"]))
        if py_path.is_file():
            py_text = py_path.read_text(encoding="utf-8")
    d, unsupported = lower_panther(doc, py_text, str(path))
    issues = (
        (
            LoadIssue(
                "warning", str(path), "unsupported constructs: " + ", ".join(unsupported), d.id
            ),
        )
        if unsupported
        else ()
    )
    return Bundle(detections=(d,), issues=issues)


def panther_id(doc: dict[str, AnyT], file: str) -> str:
    raw = str(doc.get("RuleID") or Path(file).stem)
    return "panther_" + re.sub(r"[^A-Za-z0-9_]", "_", raw)


def lower_panther(
    doc: dict[str, AnyT], py_text: str | None, file: str
) -> tuple[Detection, list[str]]:
    unsupported: list[str] = []
    meta: dict[str, str | int | bool] = {
        "source": "panther",
        "title": str(doc.get("DisplayName") or doc.get("RuleID", "")),
    }
    for key in ("Severity", "Description", "Enabled"):
        if key in doc and doc[key] is not None:
            meta[key.lower()] = doc[key] if isinstance(doc[key], bool | int) else str(doc[key])
    reports = (doc.get("Reports") or {}).get("MITRE ATT&CK") or []
    if reports:
        meta["mitre_attack_technique_id"] = ",".join(str(r).split(":")[-1] for r in reports)
    analysis = str(doc.get("AnalysisType"))
    if analysis == "correlation_rule":
        unsupported.append("panther:correlation_rule")
        sub = [
            str(g.get("RuleID", ""))
            for grp in (doc.get("Detection") or [])
            for g in (grp.get("Group") or [])
        ]
        meta["correlates"] = ",".join(sub)
        spec = single_event("e", Unknown(label="panther:correlation_rule", raw=",".join(sub)))
    else:
        pred = _python_pred(py_text, unsupported)
        threshold = int(doc.get("Threshold") or 1)
        if threshold > 1:
            window = Window(int(doc.get("DedupPeriodMinutes") or 60) * 60)
            spec = TraceSpec(
                events=(EventVar("e", pred),),
                window=window,
                condition=Count("e", ">=", threshold),
                options=RuleOptions(),
            )
            meta["threshold"] = threshold
        else:
            spec = single_event("e", pred)
    return (
        Detection(
            id=panther_id(doc, file),
            spec=spec,
            meta=meta,
            source=Provenance(
                file=file,
                frontend="panther",
                native_id=str(doc.get("RuleID", "")),
                unsupported=tuple(dict.fromkeys(unsupported)),
            ),
        ),
        unsupported,
    )


def _python_pred(py_text: str | None, unsupported: list[str]) -> Pred:
    unsupported.append("panther:python_logic")
    if not py_text:
        return Unknown(label="panther:python_logic", raw="<no .py file>")
    body = _rule_function(py_text) or py_text
    sets = {name: _strings(vals) for name, vals in _SET_DEF.findall(py_text)}
    methods: list[Pred] = []
    for m in _ENDSWITH.finditer(body):
        s = _first(m)
        if _METHOD_CTX.search(body[max(0, m.start() - 80) : m.start()]):
            methods.append(StrFn(field=(None, "method"), fn="endswith", value=s))
    for m in _STARTSWITH.finditer(body):
        s = _first(m)
        if _METHOD_CTX.search(body[max(0, m.start() - 80) : m.start()]):
            methods.append(StrFn(field=(None, "method"), fn="startswith", value=s))
    for m in _EQ.finditer(body):
        s = _first(m)
        ctx = body[max(0, m.start() - 80) : m.start()]
        if _METHOD_CTX.search(ctx) and _METHOD_LIKE.match(s):
            methods.append(Cmp(field=(None, "method"), op="=", value=s))
    for m in _IN_SET.finditer(body):
        ctx = body[max(0, m.start() - 80) : m.start()]
        if not _METHOD_CTX.search(ctx):
            continue
        inner = m.group(1).strip()
        vals = sets.get(inner, _strings(inner))
        vals = [v for v in vals if _METHOD_LIKE.match(v)]
        if vals:
            methods.append(In(field=(None, "method"), values=tuple(vals)))
    # `in SOME_CONSTANT` (a module-level set)
    for name, vals in sets.items():
        if re.search(r"\bin\s+" + re.escape(name) + r"\b", body) and _METHOD_CTX.search(body):
            vals = [v for v in vals if _METHOD_LIKE.match(v)]
            if vals:
                methods.append(In(field=(None, "method"), values=tuple(vals)))
    perms = [_first(m) for m in _PERM_CTX.finditer(body)]
    perms = [p for p in perms if _METHOD_LIKE.match(p)]
    parts: list[Pred] = []
    if methods:
        parts.append(any_of(_dedupe(methods)))
    if perms:
        parts.append(In(field=(None, "permission"), values=tuple(dict.fromkeys(perms))))
    parts.append(
        Unknown(
            label="panther:python_logic",
            raw=_rule_function(py_text)[:200] if _rule_function(py_text) else None,
        )
    )
    return all_of(parts)


def _rule_function(py_text: str) -> str:
    m = re.search(r"^def rule\(.*?(?=^def |\Z)", py_text, re.M | re.S)
    return m.group(0) if m else ""


def _first(m: re.Match[str]) -> str:
    return next((g for g in m.groups() if g is not None), "")


def _strings(text: str) -> list[str]:
    return [_first(m) for m in _ANY_STR.finditer(text)]


def _dedupe(preds: list[Pred]) -> list[Pred]:
    out: list[Pred] = []
    for p in preds:
        if p not in out:
            out.append(p)
    return out


__all__ = ["is_panther_gcp", "load_panther_file", "lower_panther"]

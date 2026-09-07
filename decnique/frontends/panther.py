"""Panther front-end: ``.yml`` metadata + ``.py`` detection logic -> DSL detections.

Panther's logic is arbitrary Python, so it cannot be lowered faithfully.  The
front-end recovers what is syntactically visible - method-name and permission
literals used with ``==``, ``in``, ``endswith``/``startswith`` next to
``methodName``/``permission`` - and conjoins an ``Unknown("panther:python_logic")``
atom, so the result is always *approximate* and never claims more than the rule
text shows.  A *negated* test (``!=``, ``not in``, ``not x.startswith(...)``) names
the methods the rule does **not** fire on; which ones it does fire on cannot be read
off a regex, so it becomes a don't-know rather than the opposite set.  ``Threshold`` becomes ``condition #e >= N`` with the dedup period as the
window; ``correlation_rule`` files lower to a single ``Unknown`` event.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any as AnyT

import yaml

from decnique.dsl.ast import Bundle, Detection, LoadIssue, Provenance
from decnique.frontends.panther_py import rule_predicate
from decnique.model.predicates import Cmp, Const, In, Like, Pred, StrFn, Unknown, all_of, any_of
from decnique.model.trace import Count, EventVar, RuleOptions, TraceSpec, Window, single_event

_METHOD_CTX = re.compile(r"(?:methodName|method_name|METHOD|method)\b", re.I)
_STR = r"(?:\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|'([^'\\]*(?:\\.[^'\\]*)*)')"
_ENDSWITH = re.compile(r"\.endswith\(\s*" + _STR + r"\s*\)")
_STARTSWITH = re.compile(r"\.startswith\(\s*" + _STR + r"\s*\)")
_EQ = re.compile(r"(?:==|!=)\s*" + _STR)
_STR_IN = re.compile(_STR + r"\s+in\s+([^\n:]{0,160})")  # ``"X" in <method expr>``
_IN_SET = re.compile(r"\bin\s*[\[({]([^\])}]*)[\])}]", re.S)
_SET_DEF = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*[\[({]([^\])}]*)[\])}]", re.M | re.S)
_ANY_STR = re.compile(_STR)
_PERM_CTX = re.compile(r"permission\W{0,10}" + _STR, re.I)
# a dotted method / permission name, or a bare CamelCase v1 method such as ``SetIamPolicy``
_METHOD_LIKE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9_.*-]*\.[A-Za-z][A-Za-z0-9_*-]*|[A-Z][a-z]+(?:[A-Z][A-Za-z0-9]*)+)$"
)


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
        pred = _rule_pred(py_text, unsupported)
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


# Panther "standard" rules test the unified data model: ``event.udm("event_type") == event_type.X``.
# For GCP.AuditLog the data model (``data_models/gcp_data_model.py``) derives exactly one event
# type — ADMIN_ROLE_ASSIGNED when a SetIamPolicy binding delta ADDs a role matching
# ``roles/owner`` or ``roles/*Admin`` — and ``None`` for everything else.  So such a rule is
# translated *exactly*: that predicate for ADMIN_ROLE_ASSIGNED, ``false`` for any other type.
_UDM_EVENT_TYPE = re.compile(r'event\.udm\(\s*"event_type"\s*\)\s*(==|in)\s*([^\n:]+)')
_DELTA_LABEL = "udm:target.resource.attribute.labels[ser_binding_deltas_{}]"


def _gcp_admin_role_assigned() -> Pred:
    role = (None, _DELTA_LABEL.format("role"))
    return all_of(
        [
            Cmp(field=(None, "method"), op="=", value="SetIamPolicy"),
            Cmp(field=(None, _DELTA_LABEL.format("action")), op="=", value="ADD"),
            any_of(
                [
                    Cmp(field=role, op="=", value="roles/owner"),
                    Like(field=role, pattern="roles/*Admin"),
                ]
            ),
        ]
    )


def _datamodel_pred(py_text: str | None) -> Pred | None:
    if not py_text:
        return None
    body = _rule_function(py_text)
    m = _UDM_EVENT_TYPE.search(body)
    if not m or body.count("event.udm(") > 1 or "return event.udm(" not in body.replace(" ", "").replace("returnevent", "return event"):
        return None  # only the plain ``return event.udm("event_type") == ...`` shape
    names = set(re.findall(r"event_type\.([A-Z_]+)", m.group(2)))
    if not names:
        return None
    if "ADMIN_ROLE_ASSIGNED" in names:
        return _gcp_admin_role_assigned()
    return Const(value=False)  # the GCP data model never yields this event type


def _rule_pred(py_text: str | None, unsupported: list[str]) -> Pred:
    """Evaluate ``rule()`` symbolically (:mod:`decnique.frontends.panther_py`); the ``event.udm``
    data-model idiom has its own exact translation; the regex scraper is the last resort when
    the body cannot be evaluated at all."""
    if not py_text:
        return _python_pred(py_text, unsupported)
    dm = _datamodel_pred(py_text)
    if dm is not None:
        return dm
    pred, missing = rule_predicate(py_text)
    if isinstance(pred, Unknown) and not pred.fields:
        return _python_pred(py_text, unsupported)  # nothing understood: scrape literals
    for what in missing:
        unsupported.append(f"panther:python:{what}")
    return pred


def _python_pred(py_text: str | None, unsupported: list[str]) -> Pred:
    unsupported.append("panther:python_logic")
    if not py_text:
        return Unknown(label="panther:python_logic", raw="<no .py file>")
    body = _rule_function(py_text) or py_text
    sets = {name: _strings(vals) for name, vals in _SET_DEF.findall(py_text)}
    methods: list[Pred] = []
    negated = False  # a negated method test: the rule fires on the OTHER methods

    def positive(pos: int) -> bool:
        """Is the test at ``pos`` a *positive* test on the method name?

        A negated one (``!=``, ``not in``, ``not x.startswith(...)``) records `negated`
        instead: a regex cannot say which methods such a rule fires on, and scraping the
        literals would claim the exact opposite set (honesty invariant #1)."""
        nonlocal negated
        receiver, neg = _receiver(body, pos)
        if not _METHOD_CTX.search(receiver):
            return False
        negated = negated or neg
        return not neg

    for m in _ENDSWITH.finditer(body):
        if positive(m.start()):
            methods.append(StrFn(field=(None, "method"), fn="endswith", value=_first(m)))
    for m in _STARTSWITH.finditer(body):
        if positive(m.start()):
            methods.append(StrFn(field=(None, "method"), fn="startswith", value=_first(m)))
    for m in _STR_IN.finditer(body):  # substring test on the method name
        s = _first(m)
        if _METHOD_CTX.search(m.group(m.lastindex)) and _METHOD_LIKE.match(s):
            if _receiver(body, m.start())[1]:
                negated = True
            else:
                methods.append(StrFn(field=(None, "method"), fn="contains", value=s))
    for m in _EQ.finditer(body):
        s = _first(m)
        if not _METHOD_LIKE.match(s):
            continue
        if body[m.start():m.start() + 2] == "!=":
            if _METHOD_CTX.search(_receiver(body, m.start())[0]):
                negated = True
        elif positive(m.start()):
            methods.append(Cmp(field=(None, "method"), op="=", value=s))
    for m in _IN_SET.finditer(body):
        if not positive(m.start()):
            continue
        inner = m.group(1).strip()
        vals = [v for v in sets.get(inner, _strings(inner)) if _METHOD_LIKE.match(v)]
        if vals:
            methods.append(In(field=(None, "method"), values=tuple(vals)))
    # `in SOME_CONSTANT` (a module-level set)
    for name, vals in sets.items():
        for m in re.finditer(r"\bin\s+" + re.escape(name) + r"\b", body):
            if not positive(m.start()):
                continue
            kept = [v for v in vals if _METHOD_LIKE.match(v)]
            if kept:
                methods.append(In(field=(None, "method"), values=tuple(kept)))
    # a negated permission test names the permission the rule does NOT fire on: no claim
    perms = [
        _first(m)
        for m in _PERM_CTX.finditer(body)
        if _METHOD_LIKE.match(_first(m))
        and "!=" not in m.group(0)
        and not _receiver(body, m.start())[1]
    ]
    parts: list[Pred] = []
    if methods and not negated:
        parts.append(any_of(_dedupe(methods)))
    elif negated:
        # the scraped literals are the methods the rule EXCLUDES; which methods it fires on
        # is not knowable from a regex — say so instead of narrowing to the wrong set
        parts.append(Unknown(label="panther:negated_method_test", fields=((None, "method"),)))
    if perms:
        parts.append(In(field=(None, "permission"), values=tuple(dict.fromkeys(perms))))
    parts.append(
        Unknown(
            label="panther:python_logic",
            raw=_rule_function(py_text)[:200] if _rule_function(py_text) else None,
        )
    )
    return all_of(parts)


_RECEIVER_CUTS = ("\n", " and ", " or ", " if ", " in ", "[", "elif ", "return ")
_NOT = re.compile(r"\bnot\b")


def _receiver(body: str, pos: int, limit: int = 160) -> tuple[str, bool]:
    """The *receiver* of a test — the operand text just before ``.startswith(`` / ``==`` /
    ``in``, back to the previous operator or line — and whether that test is negated.

    Only if the receiver mentions the method name is the test a method test; a ``methodName``
    check elsewhere in the same expression must not claim a test on ``logName`` or
    ``serviceName``.  ``not`` is deliberately *not* a cut: it belongs to the test being read
    (``method not in (…)``, ``not method.startswith(…)``), and cutting there once hid the
    negation and let the scraper claim the exact set of methods the rule does not fire on."""
    chunk = body[max(0, pos - limit) : pos]
    cut = max((chunk.rfind(t) + len(t) for t in _RECEIVER_CUTS if t in chunk), default=0)
    receiver = chunk[cut:]
    return receiver, bool(_NOT.search(receiver))


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

"""Sigma front-end: generic YAML signatures -> DSL detections.

Sigma rules for GCP are all single-event (`logsource.product: gcp`).  Selections
become predicates; the ``condition`` grammar subset supported is identifiers,
``and``/``or``/``not``, parentheses, ``1 of X*``, ``all of X*``, ``1 of them`` and
``all of them``.  Aggregations (``| count() ...``) and ``keywords`` selections
lower to ``Unknown`` atoms.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any as AnyT

import yaml

from decnique.dsl.ast import Bundle, Detection, LoadIssue, Provenance
from decnique.model import event_fields as ef
from decnique.model.predicates import (
    Cmp,
    Const,
    Exists,
    InCidr,
    Like,
    Not,
    Pred,
    Regex,
    StrFn,
    Unknown,
    all_of,
    any_of,
)
from decnique.dsl.interpret import glob_has_wildcard, glob_unescape
from decnique.model.trace import RuleOptions, single_event

# Sigma / KQL have no zero-value rule: a test on an absent field is simply false, and a negated
# test (``field: null``, ``not f:*``) is true.  YARA-L's guard (every referenced field must be
# present) would make those "missing" branches dead, so these rules never fire on the events
# they were written for.
_OPTIONS = RuleOptions(allow_zero_values=True)

# Sigma GCP field names -> event-model fields (Sigma's gcp.audit taxonomy)
FIELD_MAP: dict[str, str] = {
    "gcp.audit.method_name": "method",
    "gcp.audit.methodname": "method",
    "gcp.audit.service_name": "service",
    "gcp.audit.authentication_info.principal_email": "principal",
    "gcp.audit.authorization_info.permission": "permission",
    "gcp.audit.authorization_info.granted": "granted",
    "gcp.audit.resource_name": "resource",
    "gcp.audit.request_metadata.caller_ip": "caller_ip",
    "gcp.audit.request_metadata.caller_supplied_user_agent": "user_agent",
    "data.protopayload_auditlog.methodname": "method",
    "data.protopayload_auditlog.authenticationinfo.principalemail": "principal",
    "data.protopayload_auditlog.resourcename": "resource",
    "protopayload.methodname": "method",
    "protopayload.servicename": "service",
    "protopayload.authenticationinfo.principalemail": "principal",
    "protopayload.resourcename": "resource",
    "protopayload.authorizationinfo.permission": "permission",
    "protopayload.authorizationinfo.granted": "granted",
    "data.protopayload.methodname": "method",
    "data.protopayload.servicename": "service",
    "data.protopayload.authenticationinfo.principalemail": "principal",
    "data.protopayload.resourcename": "resource",
    "data.protopayload.authorizationinfo.permission": "permission",
    "data.protopayload.authorizationinfo.granted": "granted",
    "data.protopayload.resource.type": "resource_type",
    "data.protopayload.logname": "log_name",
}
_GCP_HINT = re.compile(r"^\s*(product|service)\s*:\s*['\"]?gcp", re.M | re.I)
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "all",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
    "base64",
    "base64offset",
    "wide",
    "utf16",
    "windash",
}


def is_sigma_gcp(doc: dict[str, AnyT]) -> bool:
    ls = doc.get("logsource") or {}
    if not isinstance(ls, dict):
        return False
    product = str(ls.get("product", "")).lower()
    service = str(ls.get("service", "")).lower()
    return product == "gcp" or service.startswith("gcp")


def load_sigma_text(text: str, file: str, *, gcp_only: bool = True) -> Bundle:
    if gcp_only and not _GCP_HINT.search(text):
        return Bundle()
    try:
        docs = [d for d in yaml.load_all(text, Loader=_LOADER) if isinstance(d, dict)]
    except yaml.YAMLError as e:
        return Bundle(issues=(LoadIssue("error", file, f"sigma yaml: {e}"),))
    dets: list[Detection] = []
    issues: list[LoadIssue] = []
    for doc in docs:
        if "detection" not in doc or "title" not in doc:
            continue
        if gcp_only and not is_sigma_gcp(doc):
            continue
        d, unsupported = lower_sigma(doc, file)
        dets.append(d)
        if unsupported:
            issues.append(
                LoadIssue(
                    "warning", file, "unsupported constructs: " + ", ".join(unsupported), d.id
                )
            )
    return Bundle(detections=tuple(dets), issues=tuple(issues))


def load_sigma_file(path: Path, **kw: AnyT) -> Bundle:
    return load_sigma_text(Path(path).read_text(encoding="utf-8"), str(path), **kw)


def sigma_id(doc: dict[str, AnyT], file: str) -> str:
    raw = str(doc.get("id") or Path(file).stem)
    return "sigma_" + re.sub(r"[^A-Za-z0-9_]", "_", raw)


def lower_sigma(doc: dict[str, AnyT], file: str) -> tuple[Detection, list[str]]:
    unsupported: list[str] = []
    detection = doc.get("detection") or {}
    selections: dict[str, Pred] = {}
    for name, body in detection.items():
        if name == "condition":
            continue
        selections[name] = _selection(name, body, unsupported)
    cond_text = str(detection.get("condition", "selection"))
    pred = _condition(cond_text, selections, unsupported)
    meta: dict[str, str | int | bool] = {"source": "sigma", "title": str(doc.get("title", ""))}
    for key in ("status", "level", "author", "date", "modified", "description"):
        if key in doc and doc[key] is not None:
            meta[key] = str(doc[key])
    tags = doc.get("tags") or []
    if tags:
        meta["tags"] = ",".join(str(t) for t in tags)
    ls = doc.get("logsource") or {}
    if isinstance(ls, dict) and ls.get("service"):
        meta["logsource"] = str(ls["service"])
    return (
        Detection(
            id=sigma_id(doc, file),
            spec=single_event("e", pred, _OPTIONS),
            meta=meta,
            source=Provenance(
                file=file,
                frontend="sigma",
                native_id=str(doc.get("id", "")),
                unsupported=tuple(dict.fromkeys(unsupported)),
            ),
        ),
        unsupported,
    )


# --- selections ------------------------------------------------------------------------------


def _selection(name: str, body: AnyT, unsupported: list[str]) -> Pred:
    if isinstance(body, dict):
        return all_of([_field_clause(k, v, unsupported) for k, v in body.items()])
    if isinstance(body, list):
        parts: list[Pred] = []
        for item in body:
            if isinstance(item, dict):
                parts.append(all_of([_field_clause(k, v, unsupported) for k, v in item.items()]))
            else:
                unsupported.append(f"keywords:{name}")
                parts.append(Unknown(label="sigma:keywords", raw=str(item)))
        return any_of(parts)
    unsupported.append(f"selection:{name}")
    return Unknown(label="sigma:selection", raw=str(body))


def _field_clause(key: str, value: AnyT, unsupported: list[str]) -> Pred:
    field, *mods = key.split("|")
    mods = [m for m in mods if m]
    all_mode = "all" in mods
    mods = [m for m in mods if m != "all"]
    path = _field(field)
    values = value if isinstance(value, list) else [value]
    leaves: list[Pred] = []
    for v in values:
        leaf = _leaf(path, v, mods, unsupported, key)
        leaves.append(leaf)
    return all_of(leaves) if all_mode else any_of(leaves)


def _field(name: str) -> str:
    low = name.lower()
    if low in FIELD_MAP:
        return FIELD_MAP[low]
    return ef.udm_field(name)


def _leaf(path: str, v: AnyT, mods: list[str], unsupported: list[str], key: str) -> Pred:
    qf = (None, path)
    if v is None:
        return Not(child=Exists(field=qf))
    if any(m not in _MODIFIERS for m in mods):
        unsupported.append(f"modifier:{key}")
        return Unknown(label=f"sigma:modifier:{'|'.join(mods)}", raw=f"{key}: {v}", fields=(qf,))
    if "re" in mods:
        return Regex(field=qf, pattern=str(v))
    if "cidr" in mods:
        return InCidr(field=qf, cidrs=(str(v),))
    for m, op in (("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")):
        if m in mods:
            return Cmp(field=qf, op=op, value=_num(v))  # type: ignore[arg-type]
    if any(m in mods for m in ("base64", "base64offset", "wide", "utf16", "windash")):
        unsupported.append(f"modifier:{key}")
        return Unknown(label="sigma:modifier:encoding", raw=f"{key}: {v}", fields=(qf,))
    s = str(v)
    if path == "granted" and isinstance(v, bool | str):
        b = v if isinstance(v, bool) else {"true": True, "false": False}.get(s.lower())
        if b is not None:
            return Cmp(field=qf, op="=", value=b)
    if isinstance(v, bool | int) and not mods:
        return Cmp(field=qf, op="=", value=v)
    # Sigma escapes a literal wildcard as ``\*`` — same convention the DSL's `like` uses, so a
    # pattern passes through as is; a value without a live wildcard is an equality on the
    # unescaped text
    wild = glob_has_wildcard(s)
    if not wild:
        s = glob_unescape(s)
    nocase = True  # Sigma string matching is case-insensitive by default
    if "contains" in mods:
        return (
            Like(field=qf, pattern=f"*{s}*", nocase=nocase)
            if wild
            else StrFn(field=qf, fn="contains", value=s, nocase=nocase)
        )
    if "startswith" in mods:
        return (
            Like(field=qf, pattern=f"{s}*", nocase=nocase)
            if wild
            else StrFn(field=qf, fn="startswith", value=s, nocase=nocase)
        )
    if "endswith" in mods:
        return (
            Like(field=qf, pattern=f"*{s}", nocase=nocase)
            if wild
            else StrFn(field=qf, fn="endswith", value=s, nocase=nocase)
        )
    if wild:
        return Like(field=qf, pattern=s, nocase=nocase)
    return Cmp(field=qf, op="=", value=s, nocase=nocase)


def _num(v: AnyT) -> int | str:
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


# --- condition ---------------------------------------------------------------------------------

_TOK = re.compile(r"\(|\)|\||[^\s()|]+")


def _condition(text: str, selections: dict[str, Pred], unsupported: list[str]) -> Pred:
    if "|" in text:
        unsupported.append("condition:aggregation")
        base = text.split("|", 1)[0].strip() or "selection"
        return all_of(
            [
                _condition(base, selections, unsupported),
                Unknown(label="sigma:aggregation", raw=text),
            ]
        )
    toks = _TOK.findall(text)
    parser = _CondParser(toks, selections, unsupported)
    try:
        pred = parser.expr()
        if parser.i != len(toks):
            raise ValueError("trailing tokens")
        return pred
    except ValueError as e:
        unsupported.append(f"condition:{e}")
        return Unknown(label="sigma:condition", raw=text)


class _CondParser:
    def __init__(
        self, toks: list[str], selections: dict[str, Pred], unsupported: list[str]
    ) -> None:
        self.toks, self.i, self.sel, self.unsupported = toks, 0, selections, unsupported

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end")
        self.i += 1
        return t

    def expr(self) -> Pred:
        parts = [self.and_()]
        while self.peek() and self.peek().lower() == "or":  # type: ignore[union-attr]
            self.i += 1
            parts.append(self.and_())
        return any_of(parts)

    def and_(self) -> Pred:
        parts = [self.not_()]
        while self.peek() and self.peek().lower() == "and":  # type: ignore[union-attr]
            self.i += 1
            parts.append(self.not_())
        return all_of(parts)

    def not_(self) -> Pred:
        if self.peek() and self.peek().lower() == "not":  # type: ignore[union-attr]
            self.i += 1
            return Not(child=self.not_())
        return self.atom()

    def atom(self) -> Pred:
        t = self.take()
        if t == "(":
            e = self.expr()
            if self.take() != ")":
                raise ValueError("expected )")
            return e
        low = t.lower()
        if low in {"1", "all", "any"} or low.isdigit():
            if self.take().lower() != "of":
                raise ValueError("expected 'of'")
            target = self.take()
            names = (
                list(self.sel)
                if target.lower() == "them"
                else [n for n in self.sel if _glob(target, n)]
            )
            if not names:
                raise ValueError(f"no selection matches {target}")
            preds = [self.sel[n] for n in names]
            if low == "all":
                return all_of(preds)
            if low in {"1", "any"}:
                return any_of(preds)
            self.unsupported.append(f"condition:{low} of")
            return all_of([any_of(preds), Unknown(label="sigma:n_of", raw=f"{t} of {target}")])
        if t in self.sel:
            return self.sel[t]
        raise ValueError(f"unknown selection {t}")


def _glob(pattern: str, name: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(name, pattern)


__all__ = ["FIELD_MAP", "is_sigma_gcp", "load_sigma_file", "load_sigma_text", "lower_sigma"]


"""YARA-L 2.0 subset parser (plan §5.16): text -> :class:`YaralRule`.

Hand-written tokenizer + recursive descent rather than an Earley grammar: the
front-end must *degrade*, never fail, on a valid YARA-L rule, and per-statement
recovery (an unparsable ``events:`` statement becomes a ``RawStmt``) is simplest to
control by hand.  Keywords are case-insensitive; block and line comments are removed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SECTIONS = ("meta", "events", "match", "outcome", "condition", "options")
_KEYWORDS = {
    "and",
    "or",
    "not",
    "nocase",
    "in",
    "regex",
    "cidr",
    "over",
    "before",
    "after",
    "all",
    "any",
    "if",
    "true",
    "false",
}
_CMP_OPS = ("<=", ">=", "!=", "=", "<", ">")


class YaralSyntaxError(ValueError):
    pass


# --- AST ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldRef:
    var: str
    path: str  # dotted UDM path; map access rendered as labels[key]


@dataclass(frozen=True, slots=True)
class Placeholder:
    name: str


@dataclass(frozen=True, slots=True)
class Str:
    value: str


@dataclass(frozen=True, slots=True)
class Num:
    value: int


@dataclass(frozen=True, slots=True)
class Bool:
    value: bool


@dataclass(frozen=True, slots=True)
class Rx:
    pattern: str


@dataclass(frozen=True, slots=True)
class RefList:
    name: str


@dataclass(frozen=True, slots=True)
class Call:
    fn: str
    args: tuple[Operand, ...]


Operand = FieldRef | Placeholder | Str | Num | Bool | Rx | RefList | Call


@dataclass(frozen=True, slots=True)
class Compare:
    left: Operand
    op: str
    right: Operand
    nocase: bool = False
    quant: str | None = None


@dataclass(frozen=True, slots=True)
class InRef:
    operand: Operand
    list_name: str
    kind: str  # string | regex | cidr
    nocase: bool = False
    quant: str | None = None


@dataclass(frozen=True, slots=True)
class FuncPred:
    call: Call
    nocase: bool = False


@dataclass(frozen=True, slots=True)
class Bare:
    operand: Operand


@dataclass(frozen=True, slots=True)
class NotE:
    child: Expr


@dataclass(frozen=True, slots=True)
class AndE:
    children: tuple[Expr, ...]


@dataclass(frozen=True, slots=True)
class OrE:
    children: tuple[Expr, ...]


@dataclass(frozen=True, slots=True)
class RawStmt:
    text: str
    reason: str


Expr = Compare | InRef | FuncPred | Bare | NotE | AndE | OrE | RawStmt


@dataclass(frozen=True, slots=True)
class MatchSec:
    placeholders: tuple[str, ...]
    window: str | None  # e.g. "1h"
    anchor: str | None = None
    side: str | None = None  # before | after


@dataclass(frozen=True, slots=True)
class Outcome:
    name: str
    expr: Operand | RawStmt  # aggregate calls appear as Call("count_distinct", ...)
    raw: str


@dataclass(frozen=True, slots=True)
class CountAtom:
    name: str  # "#name" -> event var or placeholder
    op: str
    n: int


@dataclass(frozen=True, slots=True)
class VarAtom:
    name: str  # "$name" -> event var (exists) or outcome compare
    op: str | None = None
    value: int | str | None = None


@dataclass(frozen=True, slots=True)
class CondNot:
    child: Cond


@dataclass(frozen=True, slots=True)
class CondAnd:
    children: tuple[Cond, ...]


@dataclass(frozen=True, slots=True)
class CondOr:
    children: tuple[Cond, ...]


Cond = CountAtom | VarAtom | CondNot | CondAnd | CondOr | RawStmt


@dataclass(frozen=True, slots=True)
class YaralRule:
    name: str
    meta: dict[str, str]
    events: tuple[Expr, ...]
    match: MatchSec | None
    outcomes: tuple[Outcome, ...]
    condition: Cond | None
    options: dict[str, str | int | bool]
    line: int = 1
    raw_sections: dict[str, str] = field(default_factory=dict)


# --- tokenizer ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tok:
    kind: str  # FIELD PH STR NUM RX REF NAME COUNT OP NL BT
    text: str
    pos: int


_TOKEN_RE = re.compile(
    r"""
    (?P<NL>\n)
  | (?P<WS>[ \t\r]+)
  | (?P<FIELD>\$[A-Za-z_][A-Za-z0-9_]*
               (?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])+(?:\[\s*"[^"]*"\s*\])?)
  | (?P<PH>\$[A-Za-z_][A-Za-z0-9_]*)
  | (?P<COUNT>\#[A-Za-z_][A-Za-z0-9_]*)
  | (?P<REF>%[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
  | (?P<STR>"(?:[^"\\]|\\.)*")
  | (?P<BT>`[^`]*`)
  | (?P<NUM>[0-9]+)
  | (?P<NAME>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
  | (?P<OP><=|>=|!=|=|<|>|\(|\)|,|\+|-|\*|/)
  | (?P<BAD>.)
    """,
    re.X,
)
_RX_RE = re.compile(r"/((?:[^/\\\n]|\\.)+)/")
_RX_PREV = {"=", "!=", "(", ",", "and", "or", "not", "in"}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    # `//` comments, but not inside strings or backticks
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in {'"', "`"}:
            quote = c
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(text: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "/":
            prev = toks[-1].text.lower() if toks and toks[-1].kind != "NL" else "("
            m = _RX_RE.match(text, i)
            if m and prev in _RX_PREV:
                toks.append(Tok("RX", m.group(1).replace("\\/", "/"), i))
                i = m.end()
                continue
        m = _TOKEN_RE.match(text, i)
        assert m is not None  # BAD matches any single character
        kind = m.lastgroup or ""
        if kind != "WS":
            toks.append(Tok(kind, m.group(0), i))
        i = m.end()
    return toks


# --- sections ------------------------------------------------------------------------------

_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.I)
_SECTION_RE = re.compile(
    r"^[ \t]*(meta|events|match|outcome|condition|options)\s*:[ \t]*$", re.M | re.I
)


def split_rules(text: str) -> list[tuple[str, str, int]]:
    """(name, body, line) for every rule in a file."""
    clean = strip_comments(text)
    out: list[tuple[str, str, int]] = []
    for m in _RULE_RE.finditer(clean):
        depth, i = 1, m.end()
        while i < len(clean) and depth:
            if clean[i] == "{":
                depth += 1
            elif clean[i] == "}":
                depth -= 1
            i += 1
        body = clean[m.end() : i - 1]
        out.append((m.group(1), body, clean.count("\n", 0, m.start()) + 1))
    return out


def split_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(body))
    for k, m in enumerate(matches):
        end = matches[k + 1].start() if k + 1 < len(matches) else len(body)
        sections[m.group(1).lower()] = body[m.end() : end]
    return sections


# --- statements ----------------------------------------------------------------------------

_CONTINUE_BEFORE = {
    "and",
    "or",
    "not",
    "=",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "(",
    ",",
    "in",
    "regex",
    "cidr",
    "+",
    "-",
    "*",
    "/",
}
_CONTINUE_AFTER = {"and", "or", ")", ",", "nocase"}


def split_statements(toks: list[Tok]) -> list[list[Tok]]:
    """Split a token stream at newlines that are not inside parentheses and do not
    continue an expression."""
    stmts: list[list[Tok]] = []
    cur: list[Tok] = []
    depth = 0
    for k, t in enumerate(toks):
        if t.kind == "NL":
            nxt = next((x for x in toks[k + 1 :] if x.kind != "NL"), None)
            if (
                cur
                and depth == 0
                and cur[-1].text.lower() not in _CONTINUE_BEFORE
                and (nxt is None or nxt.text.lower() not in {"and", "or"})
            ):
                stmts.append(cur)
                cur = []
            continue
        if t.text == "(":
            depth += 1
        elif t.text == ")":
            depth = max(0, depth - 1)
        cur.append(t)
    if cur:
        stmts.append(cur)
    return stmts


def render(toks: list[Tok]) -> str:
    return " ".join(t.text for t in toks)


class _P:
    def __init__(self, toks: list[Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self, k: int = 0) -> Tok | None:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def at(self, text: str) -> bool:
        t = self.peek()
        return t is not None and t.text.lower() == text

    def take(self, text: str | None = None, kind: str | None = None) -> Tok:
        t = self.peek()
        if (
            t is None
            or (text is not None and t.text.lower() != text)
            or (kind is not None and t.kind != kind)
        ):
            raise YaralSyntaxError(f"expected {text or kind} at {t.text if t else 'end'}")
        self.i += 1
        return t

    def done(self) -> bool:
        return self.i >= len(self.toks)

    # expressions
    def expr(self) -> Expr:
        left = self.and_()
        parts = [left]
        while self.at("or"):
            self.i += 1
            parts.append(self.and_())
        return parts[0] if len(parts) == 1 else OrE(tuple(parts))

    def and_(self) -> Expr:
        parts = [self.not_()]
        while self.at("and"):
            self.i += 1
            parts.append(self.not_())
        return parts[0] if len(parts) == 1 else AndE(tuple(parts))

    def not_(self) -> Expr:
        if self.at("not"):
            self.i += 1
            return NotE(self.not_())
        return self.atom()

    def atom(self) -> Expr:
        if self.at("("):
            self.i += 1
            e = self.expr()
            self.take(")")
            return e
        quant = None
        if self.at("all") or self.at("any"):
            quant = self.take().text.lower()
        left = self.operand()
        t = self.peek()
        if t is not None and t.text in _CMP_OPS:
            op = self.take().text
            right = self.operand()
            nocase = self._nocase()
            return Compare(left, op, right, nocase, quant)
        if self.at("in"):
            self.i += 1
            kind = "string"
            if self.at("regex") or self.at("cidr"):
                kind = self.take().text.lower()
            ref = self.take(kind="REF")
            nocase = self._nocase()
            return InRef(left, ref.text[1:], kind, nocase, quant)
        if isinstance(left, Call):
            return FuncPred(left, self._nocase())
        return Bare(left)

    def _nocase(self) -> bool:
        if self.at("nocase"):
            self.i += 1
            return True
        return False

    def operand(self) -> Operand:
        t = self.peek()
        if t is None:
            raise YaralSyntaxError("unexpected end of statement")
        self.i += 1
        if t.kind == "FIELD":
            return _field_ref(t.text)
        if t.kind == "PH":
            return Placeholder(t.text[1:])
        if t.kind == "STR":
            return Str(_unquote(t.text))
        if t.kind == "BT":
            return Str(t.text[1:-1])
        if t.kind == "NUM":
            return Num(int(t.text))
        if t.kind == "RX":
            return Rx(t.text)
        if t.kind == "REF":
            return RefList(t.text[1:])
        if t.kind == "NAME":
            low = t.text.lower()
            if low in {"true", "false"}:
                return Bool(low == "true")
            if self.at("("):
                self.i += 1
                args: list[Operand] = []
                if not self.at(")"):
                    args.append(self.operand())
                    while self.at(","):
                        self.i += 1
                        args.append(self.operand())
                self.take(")")
                return Call(t.text, tuple(args))
            return Str(t.text)
        raise YaralSyntaxError(f"unexpected token {t.text!r}")

    # conditions
    def cond(self) -> Cond:
        parts = [self.cond_and()]
        while self.at("or"):
            self.i += 1
            parts.append(self.cond_and())
        return parts[0] if len(parts) == 1 else CondOr(tuple(parts))

    def cond_and(self) -> Cond:
        parts = [self.cond_not()]
        while self.at("and"):
            self.i += 1
            parts.append(self.cond_not())
        return parts[0] if len(parts) == 1 else CondAnd(tuple(parts))

    def cond_not(self) -> Cond:
        if self.at("not"):
            self.i += 1
            return CondNot(self.cond_not())
        if self.at("("):
            self.i += 1
            c = self.cond()
            self.take(")")
            return c
        t = self.take()
        if t.kind == "COUNT":
            op_t = self.peek()
            if op_t is not None and op_t.text in _CMP_OPS:
                self.i += 1
                n = self.take(kind="NUM")
                return CountAtom(t.text[1:], op_t.text, int(n.text))
            return CountAtom(t.text[1:], ">=", 1)
        if t.kind == "PH":
            op_t = self.peek()
            if op_t is not None and op_t.text in _CMP_OPS:
                self.i += 1
                v = self.take()
                value: int | str = (
                    int(v.text)
                    if v.kind == "NUM"
                    else _unquote(v.text)
                    if v.kind == "STR"
                    else v.text
                )
                return VarAtom(t.text[1:], op_t.text, value)
            return VarAtom(t.text[1:])
        raise YaralSyntaxError(f"unexpected {t.text!r} in condition")


def _field_ref(text: str) -> FieldRef:
    m = re.fullmatch(
        r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z0-9_.\[\]]+?)(?:\[\s*\"([^\"]*)\"\s*\])?", text
    )
    assert m, text
    var, path, key = m.group(1), m.group(2), m.group(3)
    if key is not None:
        path = f"{path}[{key}]"
    return FieldRef(var, path)


def _unquote(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s[1:-1])


# --- rule parsing --------------------------------------------------------------------------


def parse_rules(text: str) -> list[YaralRule]:
    return [_parse_rule(name, body, line) for name, body, line in split_rules(text)]


def _parse_rule(name: str, body: str, line: int) -> YaralRule:
    sections = split_sections(body)
    meta = dict(
        re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"', sections.get("meta", ""))
    )
    events = tuple(_parse_statements(sections.get("events", "")))
    match = _parse_match(sections.get("match")) if "match" in sections else None
    outcomes = tuple(_parse_outcomes(sections.get("outcome", "")))
    condition = _parse_condition(sections.get("condition")) if "condition" in sections else None
    options: dict[str, str | int | bool] = {}
    for k, v in re.findall(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(true|false|[0-9]+|\"[^\"]*\")",
        sections.get("options", ""),
        re.I,
    ):
        options[k] = (
            True
            if v.lower() == "true"
            else False
            if v.lower() == "false"
            else int(v)
            if v.isdigit()
            else v.strip('"')
        )
    return YaralRule(name, meta, events, match, outcomes, condition, options, line, sections)


def _parse_statements(text: str) -> list[Expr]:
    out: list[Expr] = []
    try:
        toks = tokenize(text)
    except YaralSyntaxError as e:
        return [RawStmt(text.strip(), f"tokenize: {e}")]
    for stmt in split_statements(toks):
        p = _P(stmt)
        try:
            e = p.expr()
            if not p.done():
                raise YaralSyntaxError(f"trailing tokens from {p.peek().text!r}")  # type: ignore[union-attr]
            out.append(e)
        except YaralSyntaxError as err:
            out.append(RawStmt(render(stmt), str(err)))
    return out


_MATCH_RE = re.compile(
    r"^\s*((?:\$[A-Za-z_][A-Za-z0-9_]*\s*,?\s*)+)\s*over\s+([0-9]+[smhd])(?:\s+(before|after)\s+\$([A-Za-z_][A-Za-z0-9_]*))?\s*$",
    re.I | re.S,
)


def _parse_match(text: str | None) -> MatchSec | None:
    if text is None:
        return None
    m = _MATCH_RE.match(text.strip())
    if not m:
        phs = tuple(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", text))
        w = re.search(r"over\s+([0-9]+[smhd])", text, re.I)
        return MatchSec(phs, w.group(1) if w else None)
    phs = tuple(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", m.group(1)))
    return MatchSec(phs, m.group(2), m.group(4), m.group(3).lower() if m.group(3) else None)


def _parse_outcomes(text: str) -> list[Outcome]:
    out: list[Outcome] = []
    try:
        toks = tokenize(text)
    except YaralSyntaxError:
        return [Outcome("?", RawStmt(text.strip(), "tokenize"), text.strip())]
    for stmt in split_statements(toks):
        if len(stmt) < 3 or stmt[0].kind != "PH" or stmt[1].text != "=":
            out.append(Outcome("?", RawStmt(render(stmt), "not an assignment"), render(stmt)))
            continue
        name = stmt[0].text[1:]
        p = _P(stmt[2:])
        try:
            expr = _outcome_expr(p)
            if not p.done():
                raise YaralSyntaxError("trailing tokens")
            out.append(Outcome(name, expr, render(stmt)))
        except YaralSyntaxError as e:
            out.append(Outcome(name, RawStmt(render(stmt), str(e)), render(stmt)))
    return out


def _outcome_expr(p: _P) -> Operand:
    """Outcome expressions: operands with + - * / arithmetic, rendered as nested Calls."""
    left = _outcome_term(p)
    while p.at("+") or p.at("-"):
        op = p.take().text
        right = _outcome_term(p)
        left = Call(op, (left, right))
    return left


def _outcome_term(p: _P) -> Operand:
    left = p.operand()
    while p.at("*") or p.at("/"):
        op = p.take().text
        right = p.operand()
        left = Call(op, (left, right))
    return left


def _parse_condition(text: str | None) -> Cond | None:
    if text is None:
        return None
    try:
        toks = [t for t in tokenize(text) if t.kind != "NL"]
        if not toks:
            return None
        p = _P(toks)
        c = p.cond()
        if not p.done():
            raise YaralSyntaxError("trailing tokens")
        return c
    except YaralSyntaxError as e:
        return RawStmt(text.strip(), str(e))

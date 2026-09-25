"""The declarative expression language shared by rules and derivations (PLAN §8.3, §12.1).

There is no ``eval`` anywhere: expressions are parsed into a small AST and statically checked
against the SBM schema before a rule or derivation is accepted into a pack.

Grammar (v0)::

    expr       := or_expr
    or_expr    := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | comparison
    comparison := operand (CMP operand)?
    CMP        := "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "contains" | "∋" | "matches"
    operand    := literal | list | quantifier | exists | ref | "(" expr ")"
    quantifier := ("any" | "all" | "none" | "count") "(" EntityType ["where" expr] [":" expr] ")"
    exists     := "exists" "(" ref ")"
    ref        := IDENT ("." IDENT)*
    list       := "[" [item ("," item)*] "]"         # bare words inside a list are strings
    literal    := INT | 'string' | "string" | "true" | "false"

Name resolution:

* a single identifier is an attribute of the entity in scope (``idle_timeout_s``), or ``key``;
* ``Device.<attr>`` is a device attribute;
* any other dotted name is a derived fact id (``management.telnet_reachable``).

Evaluation (M1) uses Kleene three-valued logic, so a missing fact can never silently turn into
a PASS; see ``docs/spec/rule-language.md``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, get_args

from kasauti.sbm.entities import ENTITY_TYPES

# --- AST --------------------------------------------------------------------------------------

Scalar = bool | int | str


@dataclass(frozen=True, slots=True)
class Lit:
    value: Scalar


@dataclass(frozen=True, slots=True)
class ListLit:
    items: tuple[Scalar, ...]


@dataclass(frozen=True, slots=True)
class Ref:
    parts: tuple[str, ...]

    @property
    def dotted(self) -> str:
        return ".".join(self.parts)


@dataclass(frozen=True, slots=True)
class Not:
    operand: Expr


@dataclass(frozen=True, slots=True)
class BoolOp:
    op: Literal["and", "or"]
    operands: tuple[Expr, ...]


CompareOp = Literal["==", "!=", "<", "<=", ">", ">=", "in", "contains", "matches"]


@dataclass(frozen=True, slots=True)
class Compare:
    op: CompareOp
    left: Expr
    right: Expr


QuantKind = Literal["any", "all", "none", "count"]


@dataclass(frozen=True, slots=True)
class Quant:
    kind: QuantKind
    entity: str
    where: Expr | None
    test: Expr | None


@dataclass(frozen=True, slots=True)
class Exists:
    ref: Ref


Expr = Lit | ListLit | Ref | Not | BoolOp | Compare | Quant | Exists


# --- Lexer ------------------------------------------------------------------------------------


class ExprError(ValueError):
    def __init__(self, message: str, source: str, pos: int) -> None:
        super().__init__(f"{message} at column {pos + 1}: {source!r}")
        self.pos = pos


KEYWORDS = frozenset(
    {
        "and",
        "or",
        "not",
        "in",
        "contains",
        "matches",
        "any",
        "all",
        "none",
        "count",
        "exists",
        "where",
        "true",
        "false",
    }
)
_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>\d+(?![A-Za-z_]))
  | (?P<str>'[^']*'|"[^"]*")
  | (?P<ident>[A-Za-z_][A-Za-z0-9_\-]*)
  | (?P<op>==|!=|<=|>=|<|>|∋)
  | (?P<punct>[()\[\],:.])
    """,
    re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class _Tok:
    kind: Literal["num", "str", "ident", "kw", "op", "punct", "eof"]
    text: str
    pos: int


def _lex(source: str) -> list[_Tok]:
    toks: list[_Tok] = []
    pos = 0
    while pos < len(source):
        m = _TOKEN.match(source, pos)
        if m is None:
            raise ExprError(f"unexpected character {source[pos]!r}", source, pos)
        kind = m.lastgroup
        text = m.group()
        if kind == "ident" and text in KEYWORDS:
            toks.append(_Tok("kw", text, pos))
        elif kind == "op" and text == "∋":
            toks.append(_Tok("kw", "contains", pos))
        elif kind in ("num", "str", "ident", "op", "punct"):
            toks.append(_Tok(kind, text, pos))  # type: ignore[arg-type]
        pos = m.end()
    toks.append(_Tok("eof", "", len(source)))
    return toks


# --- Parser -----------------------------------------------------------------------------------

_CMP_OPS: frozenset[str] = frozenset({"==", "!=", "<", "<=", ">", ">="})
_CMP_KWS: frozenset[str] = frozenset({"in", "contains", "matches"})
_QUANTS: frozenset[str] = frozenset({"any", "all", "none", "count"})


class _Parser:
    def __init__(self, source: str) -> None:
        self.source = source
        self.toks = _lex(source)
        self.i = 0

    # helpers
    def peek(self) -> _Tok:
        return self.toks[self.i]

    def take(self) -> _Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def at(self, kind: str, text: str | None = None) -> bool:
        tok = self.peek()
        return tok.kind == kind and (text is None or tok.text == text)

    def expect(self, kind: str, text: str | None = None) -> _Tok:
        if not self.at(kind, text):
            tok = self.peek()
            want = text or kind
            got = tok.text or "end of expression"
            raise ExprError(f"expected {want!r}, got {got!r}", self.source, tok.pos)
        return self.take()

    def fail(self, message: str) -> ExprError:
        return ExprError(message, self.source, self.peek().pos)

    # grammar
    def parse(self) -> Expr:
        expr = self.or_expr()
        if not self.at("eof"):
            raise self.fail(f"unexpected {self.peek().text!r}")
        return expr

    def or_expr(self) -> Expr:
        items = [self.and_expr()]
        while self.at("kw", "or"):
            self.take()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else BoolOp("or", tuple(items))

    def and_expr(self) -> Expr:
        items = [self.not_expr()]
        while self.at("kw", "and"):
            self.take()
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else BoolOp("and", tuple(items))

    def not_expr(self) -> Expr:
        if self.at("kw", "not"):
            self.take()
            return Not(self.not_expr())
        return self.comparison()

    def comparison(self) -> Expr:
        left = self.operand()
        tok = self.peek()
        if (tok.kind == "op" and tok.text in _CMP_OPS) or (
            tok.kind == "kw" and tok.text in _CMP_KWS
        ):
            self.take()
            right = self.operand()
            return Compare(tok.text, left, right)  # type: ignore[arg-type]
        return left

    def operand(self) -> Expr:
        tok = self.peek()
        if tok.kind == "num":
            self.take()
            return Lit(int(tok.text))
        if tok.kind == "str":
            self.take()
            return Lit(tok.text[1:-1])
        if tok.kind == "kw" and tok.text in ("true", "false"):
            self.take()
            return Lit(tok.text == "true")
        if tok.kind == "kw" and tok.text in _QUANTS:
            return self.quantifier()
        if tok.kind == "kw" and tok.text == "exists":
            self.take()
            self.expect("punct", "(")
            ref = self.ref()
            self.expect("punct", ")")
            return Exists(ref)
        if tok.kind == "punct" and tok.text == "[":
            return self.list_lit()
        if tok.kind == "punct" and tok.text == "(":
            self.take()
            inner = self.or_expr()
            self.expect("punct", ")")
            return inner
        if tok.kind == "ident":
            return self.ref()
        raise self.fail(f"unexpected {tok.text or 'end of expression'!r}")

    def quantifier(self) -> Quant:
        kind = self.take().text
        self.expect("punct", "(")
        entity = self.expect("ident").text
        where = test = None
        if self.at("kw", "where"):
            self.take()
            where = self.or_expr()
        if self.at("punct", ":"):
            self.take()
            test = self.or_expr()
        self.expect("punct", ")")
        return Quant(kind, entity, where, test)  # type: ignore[arg-type]

    def ref(self) -> Ref:
        parts = [self.expect("ident").text]
        while self.at("punct", "."):
            self.take()
            parts.append(self.expect("ident").text)
        return Ref(tuple(parts))

    def list_lit(self) -> ListLit:
        self.expect("punct", "[")
        items: list[Scalar] = []
        while not self.at("punct", "]"):
            tok = self.take()
            if tok.kind == "num":
                items.append(int(tok.text))
            elif tok.kind == "str":
                items.append(tok.text[1:-1])
            elif tok.kind in ("ident", "kw"):
                items.append(tok.text)
            else:
                raise ExprError(f"unexpected {tok.text!r} in list", self.source, tok.pos)
            if not self.at("punct", "]"):
                self.expect("punct", ",")
        self.take()
        return ListLit(tuple(items))


def parse(source: str) -> Expr:
    """Parse an expression. Raises :class:`ExprError` with a column number on bad input."""
    return _Parser(source).parse()


def parse_scope(source: str) -> tuple[str, Expr | None]:
    """Parse a rule's ``for_each`` clause: ``EntityType [where expr]``."""
    p = _Parser(source)
    entity = p.expect("ident").text
    where = None
    if p.at("kw", "where"):
        p.take()
        where = p.or_expr()
    if not p.at("eof"):
        raise p.fail(f"unexpected {p.peek().text!r}")
    return entity, where


# --- Static checking --------------------------------------------------------------------------

Type = Literal["bool", "int", "str", "set", "list"]


def attribute_type(entity_type: str, attr: str) -> Type | None:
    """The value type of ``entity_type.attr``, or None if there's no such attribute."""
    cls = ENTITY_TYPES.get(entity_type)
    if cls is None:
        return None
    if attr == "key":
        return "str"  # every entity's identity, e.g. the service kind or the vty range
    if attr == "type" or attr not in cls.model_fields:
        return None
    annotation: Any = cls.model_fields[attr].annotation
    meta = getattr(annotation, "__pydantic_generic_metadata__", None)
    if not meta or not meta.get("args"):
        return None
    arg = meta["args"][0]
    if arg is bool:
        return "bool"
    if arg is int:
        return "int"
    if arg is str:
        return "str"
    if get_args(arg) and get_args(arg)[0] == frozenset[str]:
        return "set"
    return None


def check(
    expr: Expr,
    *,
    scope: str | None,
    derived: Mapping[str, Type] | None = None,
    want: Type = "bool",
) -> list[str]:
    """Return a list of human-readable errors; empty means the expression is well-typed."""
    errors: list[str] = []
    got = _infer(expr, scope, derived or {}, errors)
    if got is not None and got != want:
        errors.append(f"expression has type {got}, expected {want}")
    return errors


def _infer(  # noqa: PLR0912 - one branch per AST node is the clearest form
    expr: Expr, scope: str | None, derived: Mapping[str, Type], errors: list[str]
) -> Type | None:
    match expr:
        case Lit(value=bool()):
            return "bool"
        case Lit(value=int()):
            return "int"
        case Lit():
            return "str"
        case ListLit():
            return "list"
        case Ref(parts=(attr,)):
            if scope is None:
                errors.append(f"{attr!r}: bare attribute names need an entity in scope")
                return None
            t = attribute_type(scope, attr)
            if t is None:
                errors.append(f"{scope} has no attribute {attr!r}")
            return t
        case Ref(parts=("Device", attr)):
            t = attribute_type("Device", attr)
            if t is None:
                errors.append(f"Device has no attribute {attr!r}")
            return t
        case Ref() as ref:
            if ref.dotted not in derived:
                errors.append(f"unknown derived fact {ref.dotted!r}")
                return None
            return derived[ref.dotted]
        case Exists(ref=ref):
            _infer(ref, scope, derived, errors)
            return "bool"
        case Not(operand=inner):
            _require(inner, "bool", "not", scope=scope, derived=derived, errors=errors)
            return "bool"
        case BoolOp(op=op, operands=items):
            for item in items:
                _require(item, "bool", op, scope=scope, derived=derived, errors=errors)
            return "bool"
        case Quant(kind=kind, entity=entity, where=where, test=test):
            if entity not in ENTITY_TYPES:
                errors.append(f"unknown entity type {entity!r}")
                return "int" if kind == "count" else "bool"
            if where is not None:
                _require(where, "bool", "where", scope=entity, derived=derived, errors=errors)
            if test is not None:
                _require(test, "bool", kind, scope=entity, derived=derived, errors=errors)
            elif kind == "all":
                errors.append("all(...) needs a ':' test")
            return "int" if kind == "count" else "bool"
        case Compare(op=op, left=left, right=right):
            lt = _infer(left, scope, derived, errors)
            rt = _infer(right, scope, derived, errors)
            if lt is None or rt is None:
                return "bool"
            _check_compare(op, lt, rt, right, errors)
            return "bool"
    raise AssertionError(f"unhandled node {expr!r}")  # pragma: no cover


def _require(
    expr: Expr,
    want: Type,
    ctx: str,
    *,
    scope: str | None,
    derived: Mapping[str, Type],
    errors: list[str],
) -> None:
    got = _infer(expr, scope, derived, errors)
    if got is not None and got != want:
        errors.append(f"operand of {ctx!r} has type {got}, expected {want}")


def _check_compare(op: str, lt: Type, rt: Type, right: Expr, errors: list[str]) -> None:
    if op in ("==", "!="):
        if lt != rt:
            errors.append(f"cannot compare {lt} {op} {rt}")
    elif op in ("<", "<=", ">", ">="):
        if lt != "int" or rt != "int":
            errors.append(f"{op!r} needs int operands, got {lt} and {rt}")
    elif op == "in":
        if lt not in ("str", "int") or rt not in ("list", "set"):
            errors.append(
                f"'in' needs a scalar on the left and a list/set on the right, got {lt} in {rt}"
            )
    elif op == "contains":
        if lt not in ("set", "list") or rt not in ("str", "int"):
            errors.append(
                f"'contains' needs a set on the left and a scalar on the right, "
                f"got {lt} contains {rt}"
            )
    elif op == "matches" and (
        lt != "str" or not isinstance(right, Lit) or not isinstance(right.value, str)
    ):
        errors.append(
            "'matches' needs a string attribute on the left and a quoted pattern on the right"
        )

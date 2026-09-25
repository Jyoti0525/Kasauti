"""Derived device-level facts (PLAN §8.3).

A vendor mapping only says what *its* line means locally ("this vty range allows telnet"). The
security meaning ("is telnet reachable at all?") is written once, here, as a small versioned
formula in the shared expression language, and it holds for every vendor.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from kasauti.rules import expr as ex

DERIVED_ID = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
"""Dotted, so it can never be confused with a bare attribute name, e.g.
``management.telnet_reachable``."""


class Derivation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Annotated[str, StringConstraints(pattern=DERIVED_ID)]
    version: int = Field(ge=1)
    type: ex.Type
    description: str = Field(min_length=5)
    expr: str

    @model_validator(mode="after")
    def _parses(self) -> Self:
        if self.type not in ("bool", "int", "str"):
            raise ValueError("derived facts are bool, int or str")
        ex.parse(self.expr)
        return self

    @property
    def ast(self) -> ex.Expr:
        return ex.parse(self.expr)

    def references(self) -> frozenset[str]:
        """Other derived facts this formula reads."""
        return frozenset(_derived_refs(self.ast))


def _derived_refs(node: ex.Expr) -> Iterable[str]:
    match node:
        case ex.Ref(parts=parts) if len(parts) > 1 and parts[0] != "Device":
            yield ".".join(parts)
        case ex.Not(operand=inner):
            yield from _derived_refs(inner)
        case ex.BoolOp(operands=items):
            for item in items:
                yield from _derived_refs(item)
        case ex.Compare(left=left, right=right):
            yield from _derived_refs(left)
            yield from _derived_refs(right)
        case ex.Quant(where=where, test=test):
            for part in (where, test):
                if part is not None:
                    yield from _derived_refs(part)
        case ex.Exists(ref=ref):
            yield from _derived_refs(ref)
        case _:
            return


class DerivationError(ValueError):
    pass


def order_and_check(derivations: Iterable[Derivation]) -> list[Derivation]:
    """Type-check every formula and return them in dependency order.

    Raises :class:`DerivationError` listing every problem: duplicates, unknown references,
    type errors and cycles.
    """
    by_id: dict[str, Derivation] = {}
    problems: list[str] = []
    for d in derivations:
        if d.id in by_id:
            problems.append(f"{d.id}: defined twice")
        by_id[d.id] = d
    types = {d.id: d.type for d in by_id.values()}
    for d in by_id.values():
        problems += [
            f"{d.id}: {e}" for e in ex.check(d.ast, scope=None, derived=types, want=d.type)
        ]
    if problems:
        raise DerivationError("; ".join(problems))

    ordered: list[Derivation] = []
    state: dict[str, int] = {}  # 1 = visiting, 2 = done

    def visit(node: str, trail: tuple[str, ...]) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            raise DerivationError("cycle: " + " -> ".join((*trail, node)))
        state[node] = 1
        for dep in sorted(by_id[node].references()):
            visit(dep, (*trail, node))
        state[node] = 2
        ordered.append(by_id[node])

    for ident in sorted(by_id):
        visit(ident, ())
    return ordered

"""Inferences and exposures: two small kinds of pack content in the expression language.

**Inferences** (PLAN §7 role inference, §12.7 untrusted interfaces) fill facts a configuration
implies but never states, such as "this interface faces the internet" from its zone or
description. They are data (``packs/inferences/*.yaml``), vendor-neutral, and only fill
*absent* facts: an admin's explicit role always wins (TODO M2.21, M2.22).

**Exposures** (PLAN §12.7, TODO M2.49) adjust a finding's severity by one level each: *raise*
when the weakness is reachable from an untrusted side, *lower* when a compensating control
exists. The result reads like the plan's example: "High (base) → Critical: telnet is reachable
while an untrusted interface has no inbound filter".
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from kasauti.rules import expr as ex
from kasauti.rules.derivation import DERIVED_ID, Derivation
from kasauti.rules.evaluate import Evaluator, Known, derive, evidence_of
from kasauti.rules.model import Severity
from kasauti.sbm.document import SecurityBaselineModel
from kasauti.sbm.entities import ENTITY_TYPES, Entity
from kasauti.sbm.facts import Evidence, FactState


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


# --- inferences ------------------------------------------------------------------------------


class Inference(_Strict):
    id: Annotated[str, StringConstraints(pattern=DERIVED_ID)]
    """Dotted, e.g. ``interface.role.untrusted_by_name``."""
    version: int = Field(ge=1)
    description: str = Field(min_length=5)
    for_each: str
    when: str
    set: dict[str, ex.Scalar] = Field(min_length=1)
    """Attribute -> value, filled only where the attribute is still absent."""

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        entity, _ = ex.parse_scope(self.for_each)
        if entity not in ENTITY_TYPES:
            raise ValueError(f"for_each: unknown entity type {entity!r}")
        ex.parse(self.when)
        for attr, value in self.set.items():
            kind = ex.attribute_type(entity, attr)
            if kind is None or attr == "key":
                raise ValueError(f"{entity} has no attribute {attr!r}")
            if not _fits(kind, value):
                raise ValueError(f"{entity}.{attr} is {kind}-valued; {value!r} doesn't fit")
        return self

    @property
    def scope(self) -> tuple[str, ex.Expr | None]:
        return ex.parse_scope(self.for_each)

    def check(self, derived: Mapping[str, ex.Type]) -> list[str]:
        entity, where = self.scope
        errors: list[str] = []
        if where is not None:
            errors += [f"for_each: {e}" for e in ex.check(where, scope=entity, derived=derived)]
        errors += [
            f"when: {e}" for e in ex.check(ex.parse(self.when), scope=entity, derived=derived)
        ]
        return errors


def _fits(kind: str, value: ex.Scalar) -> bool:
    return {
        "bool": isinstance(value, bool),
        "int": isinstance(value, int) and not isinstance(value, bool),
        "str": isinstance(value, str),
    }.get(kind, False)


def apply_inferences(
    sbm: SecurityBaselineModel,
    inferences: Sequence[Inference],
    derivations: Sequence[Derivation],
) -> SecurityBaselineModel:
    """Apply inferences in file order. The first inference to fill an attribute wins.

    Expressions see the defaults view: an inference enriches the model, it doesn't judge it.
    An inferred fact is ``explicit``, and its evidence is the lines that made the condition
    true, re-labelled with the inference id so a reader sees *why* (``inference/…@1``).
    """
    for inf in inferences:
        derived = derive(sbm, derivations, use_defaults=True)
        ev = Evaluator(sbm, use_defaults=True, derived=derived)
        entity_type, where = inf.scope
        where_expr = where
        when = ex.parse(inf.when)
        replaced: dict[tuple[str, str], Entity] = {}
        for entity in ev.members(entity_type):
            targets = [a for a in inf.set if getattr(entity, a).state is FactState.ABSENT]
            if not targets:
                continue
            if where_expr is not None:
                w = ev.eval(where_expr, entity)
                if not (isinstance(w, Known) and w.value is True):
                    continue
            result = ev.eval(when, entity)
            if not (isinstance(result, Known) and result.value is True):
                continue
            evidence = _relabel(evidence_of(result.why), inf)
            updates: dict[str, Any] = {}
            for attr in targets:
                fact_cls = type(getattr(entity, attr))  # the concrete Fact[str], Fact[bool], …
                if evidence:
                    updates[attr] = fact_cls.explicit(inf.set[attr], *evidence)
                else:  # decided by vendor defaults alone
                    sources = sorted({o.default_source for o in result.why if o.default_source})
                    note = f"inference/{inf.id}@{inf.version}"
                    updates[attr] = fact_cls.vendor_default(
                        inf.set[attr], ", ".join([note, *sources])
                    )
            replaced[_ident(entity)] = entity.model_copy(update=updates)
        if replaced:
            sbm = _replace(sbm, replaced)
    return sbm


def _relabel(evidence: Iterable[Evidence], inf: Inference) -> tuple[Evidence, ...]:
    return tuple(
        e.model_copy(
            update={
                "mapping_id": f"inference/{inf.id}",
                "mapping_version": inf.version,
                "approved_by": ("maintainer",),
            }
        )
        for e in evidence
    )


def _replace(
    sbm: SecurityBaselineModel, replaced: Mapping[tuple[str, str], Entity]
) -> SecurityBaselineModel:
    device = replaced.get(("Device", sbm.device.key), sbm.device)
    present = {_ident(e) for e in sbm.entities}
    entities = [replaced.get(_ident(e), e) for e in sbm.entities]
    # Singletons the evaluator materialised (never mentioned in the config) join the model now.
    entities += [
        e for ident, e in replaced.items() if ident[0] != "Device" and ident not in present
    ]
    # Built through the constructor (not model_copy) so canonical order and checks re-run.
    return SecurityBaselineModel(
        sbm_version=sbm.sbm_version,
        device=device,  # type: ignore[arg-type]
        entities=tuple(entities),  # type: ignore[arg-type]
        derived=sbm.derived,
        known_empty=sbm.known_empty,
        unread=sbm.unread,
    )


def _ident(entity: Entity) -> tuple[str, str]:
    return (type(entity).__name__, entity.key)


def apply_default_role(
    sbm: SecurityBaselineModel, role: str | None, source: str
) -> SecurityBaselineModel:
    """The vendor pack's usual role, as a ``vendor_default``, when nothing inferred one."""
    if role is None or sbm.device.role.state is not FactState.ABSENT:
        return sbm
    role_fact = type(sbm.device.role).vendor_default(role, source)
    device = sbm.device.model_copy(update={"role": role_fact})
    return sbm.model_copy(update={"device": device})


# --- exposures -------------------------------------------------------------------------------

_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


class Exposure(_Strict):
    id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
    direction: Literal["raise", "lower"]
    scopes: tuple[str, ...] = Field(min_length=1)
    """Entity types a rule may be quantified over to use this exposure."""
    when: str
    explain: str = Field(min_length=5)

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        bad = [s for s in self.scopes if s not in ENTITY_TYPES]
        if bad:
            raise ValueError(f"unknown entity types {bad}")
        ex.parse(self.when)
        return self

    def check(self, derived: Mapping[str, ex.Type]) -> list[str]:
        return [
            f"when ({scope}): {e}"
            for scope in self.scopes
            for e in ex.check(ex.parse(self.when), scope=scope, derived=derived)
        ]


def adjust_severity(
    base: Severity, exposures: Sequence[Exposure], ev: Evaluator, entity: Entity
) -> tuple[Severity, str, tuple[Evidence, ...]]:
    """Apply each exposure whose condition is TRUE, one level each, and explain the result."""
    level = _ORDER.index(base)
    reasons: list[str] = []
    evidence: list[Evidence] = []
    for exp in exposures:
        val = ev.eval(ex.parse(exp.when), entity)
        if not (isinstance(val, Known) and val.value is True):
            continue
        step = 1 if exp.direction == "raise" else -1
        level = min(max(level + step, 0), len(_ORDER) - 1)
        reasons.append(exp.explain if step > 0 else f"compensating: {exp.explain}")
        evidence.extend(evidence_of(val.why))
    final = _ORDER[level]
    text = f"{base.value.capitalize()} (base)"
    if reasons:
        text += f" → {final.value.capitalize()}: " + "; ".join(reasons)
    return final, text, tuple(evidence)

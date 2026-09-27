"""Four-valued evaluation for rules and derivations (PLAN §8.3, §12.1; TODO M1.08, M1.10).

Values are TRUE/FALSE (or a number, string, set: :class:`Known`) and ABSENT/UNKNOWN
(:class:`Missing`); the semantics are in docs/spec/rule-language.md §3. In short:

* ``and``/``or``/``not`` are Kleene logic; UNKNOWN outranks ABSENT when both are involved.
* A comparison with a missing operand is missing.
* A quantifier over zero entities is ABSENT, unless a vendor default says the type is empty
  (``known_empty``) or some statements about the type couldn't be read (``unread``, UNKNOWN).
* With unread statements about a type, "all …" and "none …" can't be TRUE: the unread entity
  might be the exception. A found witness (``any`` TRUE, ``all``/``none`` FALSE) still counts.

Every value carries its *witnesses*: the facts that decided it, with their lines. For an
``any`` that is TRUE that's the members that made it true, not everything that was read. A
finding therefore shows the lines that matter (``transport input ssh telnet``), not the whole
config.

``use_defaults`` selects the view: with it, ``vendor_default`` facts count as known; without
it they read as ABSENT. Rules with ``on_absent: resolve_default`` use the first view,
everything else the second, so a default never silently decides a rule whose author asked
for REVIEW.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from kasauti.rules import expr as ex
from kasauti.rules import regex
from kasauti.rules.derivation import Derivation
from kasauti.sbm.document import SecurityBaselineModel, unread_subject
from kasauti.sbm.entities import ENTITY_TYPES, SINGLETON_TYPES, Entity
from kasauti.sbm.facts import Evidence, Fact, FactState


@dataclass(frozen=True, slots=True)
class Observation:
    """One fact (or entity, or derived fact) that an evaluation read."""

    subject: str
    """``MgmtSession[vty 0-4].transport``, ``MgmtSession[vty 0-4]`` or a derived fact id."""
    state: FactState | None
    value: str | None
    evidence: tuple[Evidence, ...] = ()
    default_source: str | None = None


Why = tuple[Observation, ...]


@dataclass(frozen=True, slots=True)
class Known:
    value: Any
    why: Why = ()


@dataclass(frozen=True, slots=True)
class Missing:
    kind: Literal["absent", "unknown"]
    why: Why = ()


Val = Known | Missing
TRUE = Known(True)


# --- combinators ---------------------------------------------------------------------------------


def merge(*whys: Why) -> Why:
    seen: dict[str, Observation] = {}
    for why in whys:
        for obs in why:
            seen.setdefault(obs.subject, obs)
    return tuple(seen.values())


def _missing(vals: Sequence[Missing]) -> Missing:
    kind: Literal["absent", "unknown"] = (
        "unknown" if any(v.kind == "unknown" for v in vals) else "absent"
    )
    return Missing(kind, merge(*(v.why for v in vals)))


def kleene_and(vals: Sequence[Val]) -> Val:
    falses = [v for v in vals if isinstance(v, Known) and v.value is False]
    if falses:
        return Known(False, merge(*(v.why for v in falses)))
    missing = [v for v in vals if isinstance(v, Missing)]
    if missing:
        return _missing(missing)
    return Known(True, merge(*(v.why for v in vals)))


def kleene_or(vals: Sequence[Val]) -> Val:
    trues = [v for v in vals if isinstance(v, Known) and v.value is True]
    if trues:
        return Known(True, merge(*(v.why for v in trues)))
    missing = [v for v in vals if isinstance(v, Missing)]
    if missing:
        return _missing(missing)
    return Known(False, merge(*(v.why for v in vals)))


def kleene_not(val: Val) -> Val:
    return Known(not val.value, val.why) if isinstance(val, Known) else val


def display(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, frozenset | tuple | list):
        return "{" + ", ".join(sorted(str(v) for v in value)) + "}"
    return str(value)


# --- evaluator -----------------------------------------------------------------------------------


class Evaluator:
    def __init__(
        self,
        sbm: SecurityBaselineModel,
        *,
        use_defaults: bool,
        derived: Mapping[str, Val] | None = None,
    ) -> None:
        self.sbm = sbm
        self.use_defaults = use_defaults
        self.derived: Mapping[str, Val] = derived or {}
        self._members: dict[str, tuple[Entity, ...]] = {}

    def members(self, entity_type: str) -> tuple[Entity, ...]:
        """Entities of a type. A singleton always has exactly one member: if the config never
        mentioned it, it's there with every fact absent (so "min length not set" is visible)."""
        if entity_type not in self._members:
            if entity_type == "Device":
                found: tuple[Entity, ...] = (self.sbm.device,)
            else:
                found = tuple(e for e in self.sbm.entities if e.type == entity_type)
                if not found and entity_type in SINGLETON_TYPES:
                    found = (ENTITY_TYPES[entity_type].model_validate({}),)
            self._members[entity_type] = found
        return self._members[entity_type]

    def entity(self, entity_id: str) -> Entity | None:
        """The entity a finding names, including a materialised singleton."""
        etype = entity_id.split("[", 1)[0]
        return next((e for e in self.members(etype) if e.entity_id == entity_id), None)

    def eval(self, node: ex.Expr, scope: Entity | None) -> Val:  # noqa: PLR0912 - one case per node
        match node:
            case ex.Lit(value=value):
                return Known(value)
            case ex.ListLit(items=items):
                return Known(items)
            case ex.Ref(parts=(attr,)):
                if scope is None:  # pragma: no cover - the static check requires a scope
                    raise RuntimeError(f"{attr!r} evaluated without an entity in scope")
                return self._fact(scope, attr)
            case ex.Ref(parts=("Device", attr)):
                return self._fact(self.sbm.device, attr)
            case ex.Ref() as ref:
                return self.derived[ref.dotted]
            case ex.Exists(ref=ref):
                val = self.eval(ref, scope)
                if isinstance(val, Known):
                    return Known(True, val.why)
                return Known(False, val.why) if val.kind == "absent" else val
            case ex.Not(operand=inner):
                return kleene_not(self.eval(inner, scope))
            case ex.BoolOp(op="and", operands=items):
                return kleene_and([self.eval(i, scope) for i in items])
            case ex.BoolOp(operands=items):
                return kleene_or([self.eval(i, scope) for i in items])
            case ex.Compare():
                return self._compare(node, scope)
            case ex.Quant():
                return self._quant(node)
        raise AssertionError(f"unhandled node {node!r}")  # pragma: no cover

    def _fact(self, entity: Entity, attr: str) -> Val:
        if attr == "key":
            return Known(entity.key, (Observation(entity.entity_id, None, None, entity.evidence),))
        fact: Fact[Any] = getattr(entity, attr)
        subject = f"{entity.entity_id}.{attr}"
        match fact.state:
            case FactState.EXPLICIT:
                obs = Observation(subject, fact.state, display(fact.value), fact.evidence)
                return Known(fact.value, (obs,))
            case FactState.VENDOR_DEFAULT if self.use_defaults:
                obs = Observation(
                    subject, fact.state, display(fact.value), fact.evidence, fact.default_source
                )
                return Known(fact.value, (obs,))
            case FactState.UNKNOWN:
                return Missing("unknown", (Observation(subject, fact.state, None, fact.evidence),))
        return Missing("absent", (Observation(subject, FactState.ABSENT, None),))

    def _compare(self, node: ex.Compare, scope: Entity | None) -> Val:
        left = self.eval(node.left, scope)
        right = self.eval(node.right, scope)
        if isinstance(left, Missing) or isinstance(right, Missing):
            return _missing([v for v in (left, right) if isinstance(v, Missing)])
        a, b = left.value, right.value
        match node.op:
            case "==":
                result = a == b
            case "!=":
                result = a != b
            case "<":
                result = a < b
            case "<=":
                result = a <= b
            case ">":
                result = a > b
            case ">=":
                result = a >= b
            case "in":
                result = a in b
            case "contains":
                result = b in a
            case "matches":
                result = regex.search(str(b), str(a))
        return Known(bool(result), merge(left.why, right.why))

    def _quant(self, q: ex.Quant) -> Val:
        members = self.members(q.entity)
        candidates: list[tuple[Entity, Val]] = []
        for entity in members:
            where = self.eval(q.where, entity) if q.where is not None else TRUE
            if isinstance(where, Known) and where.value is False:
                continue
            candidates.append((entity, where))
        unread = self.sbm.unread.get(q.entity, ())
        unread_obs = Observation(unread_subject(q.entity, unread), FactState.UNKNOWN, None, unread)
        if not candidates:
            return self._empty(q, members, unread_obs if unread else None)

        results: list[tuple[Val, Val]] = []
        for entity, where in candidates:
            test = self.eval(q.test, entity) if q.test is not None else TRUE
            seen = (Observation(entity.entity_id, None, None, entity.evidence),)
            test = Known(test.value, merge(seen, test.why)) if isinstance(test, Known) else test
            results.append((where, test))

        val: Val
        match q.kind:
            case "any":
                val = kleene_or([kleene_and([w, t]) for w, t in results])
            case "all":
                val = kleene_and([kleene_or([kleene_not(w), t]) for w, t in results])
            case "none":
                val = kleene_not(kleene_or([kleene_and([w, t]) for w, t in results]))
            case "count":
                flat = [v for pair in results for v in pair]
                missing = [v for v in flat if isinstance(v, Missing)]
                if missing:
                    val = _missing(missing)
                else:
                    n = sum(1 for _, t in results if isinstance(t, Known) and t.value is True)
                    val = Known(n, merge(*(v.why for v in flat)))
        if unread and isinstance(val, Known) and not _is_witness(q.kind, val):
            return Missing("unknown", merge(val.why, (unread_obs,)))
        return val

    def _empty(self, q: ex.Quant, members: tuple[Entity, ...], unread: Observation | None) -> Val:
        if unread is not None:
            return Missing("unknown", (unread,))
        source = self.sbm.known_empty.get(q.entity)
        if source and self.use_defaults and not members:
            obs = Observation(
                f"{q.entity}: none configured", FactState.VENDOR_DEFAULT, "none", (), source
            )
            vacuous = {"any": False, "all": True, "none": True, "count": 0}[q.kind]
            return Known(vacuous, (obs,))
        what = f"any {q.entity}" if not members else f"a {q.entity} matching the condition"
        return Missing("absent", (Observation(what, FactState.ABSENT, None),))


def _is_witness(kind: str, val: Known) -> bool:
    """A result that one found entity proves, whatever the unread statements say."""
    return (kind == "any" and val.value is True) or (kind in ("all", "none") and val.value is False)


# --- derivations ---------------------------------------------------------------------------------


def derive(
    sbm: SecurityBaselineModel, derivations: Iterable[Derivation], *, use_defaults: bool
) -> dict[str, Val]:
    """Evaluate derivations in (already checked) dependency order."""
    values: dict[str, Val] = {}
    for d in derivations:
        raw = Evaluator(sbm, use_defaults=use_defaults, derived=values).eval(d.ast, None)
        if isinstance(raw, Known):
            head = Observation(d.id, None, display(raw.value))
            values[d.id] = Known(raw.value, (head, *raw.why))
        else:
            values[d.id] = Missing(raw.kind, (Observation(d.id, None, None), *raw.why))
    return values


def with_derived(
    sbm: SecurityBaselineModel, derivations: Iterable[Derivation]
) -> SecurityBaselineModel:
    """The SBM with its derived facts filled in (the defaults view, as stored in reports)."""
    values = derive(sbm, derivations, use_defaults=True)
    return sbm.model_copy(update={"derived": {k: as_fact(v) for k, v in values.items()}})


def as_fact(val: Val) -> Fact[Any]:
    evidence = evidence_of(val.why)
    if isinstance(val, Missing):
        return Fact.unknown(*evidence) if val.kind == "unknown" and evidence else Fact.absent()
    sources = sorted({o.default_source for o in val.why if o.default_source})
    if sources:
        return Fact(
            value=val.value,
            state=FactState.VENDOR_DEFAULT,
            evidence=evidence,
            default_source=", ".join(sources),
        )
    return Fact.explicit(val.value, *evidence) if evidence else Fact.absent()


def evidence_of(why: Why) -> tuple[Evidence, ...]:
    """Every line behind an evaluation, de-duplicated, in file order."""
    unique = {(e.file, e.line_start, e.line_end, e.mapping_ref): e for o in why for e in o.evidence}
    return tuple(sorted(unique.values(), key=lambda e: (e.file, e.line_start, e.mapping_ref or "")))

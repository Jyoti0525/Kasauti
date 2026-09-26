"""Accumulates entities and facts while mappings run, then emits a validated SBM (PLAN §8).

How repeated statements about one attribute combine (docs/spec/mapping-language.md §3):

* a scalar ``set``/``assert``: the last statement wins, and its line is the evidence;
* ``members``: items accumulate (a negated form removes items);
* a negated ``set``: back to *absent*, so a version-scoped default can apply;
* anything *unknown*: stays unknown, and gathers every line involved. A statement we couldn't
  read might be the one that matters, so no later value can make the fact look certain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kasauti.sbm.document import SecurityBaselineModel
from kasauti.sbm.entities import ENTITY_TYPES, SINGLETON_TYPES, Device, Entity
from kasauti.sbm.facts import Evidence, FactState

EntityRef = tuple[str, str]
"""(entity type, key)"""

SINGLETON_KEYS: dict[str, str] = {
    name: str(ENTITY_TYPES[name].model_fields["key"].default) for name in SINGLETON_TYPES
}


@dataclass
class FactAcc:
    state: FactState = FactState.ABSENT
    value: Any = None
    evidence: list[Evidence] = field(default_factory=list)
    default_source: str | None = None

    def set(self, value: Any, ev: Evidence) -> None:
        if self.state is FactState.UNKNOWN:
            self.evidence.append(ev)
            return
        self.state, self.value, self.evidence = FactState.EXPLICIT, value, [ev]
        self.default_source = None

    def add(self, items: frozenset[str], ev: Evidence) -> None:
        if self.state is FactState.UNKNOWN:
            self.evidence.append(ev)
            return
        current = self.value if self.state is FactState.EXPLICIT else frozenset()
        self.state, self.value = FactState.EXPLICIT, frozenset(current | items)
        self.evidence.append(ev)
        self.default_source = None

    def remove(self, items: frozenset[str], ev: Evidence) -> None:
        if self.state is FactState.UNKNOWN:
            self.evidence.append(ev)
            return
        current = self.value if self.state is FactState.EXPLICIT else frozenset()
        self.state, self.value = FactState.EXPLICIT, frozenset(current - items)
        self.evidence.append(ev)
        self.default_source = None

    def clear(self) -> None:
        if self.state is not FactState.UNKNOWN:
            self.state, self.value, self.evidence = FactState.ABSENT, None, []

    def unknown(self, ev: Evidence) -> None:
        self.state, self.value = FactState.UNKNOWN, None
        self.default_source = None
        self.evidence.append(ev)

    def default(self, value: Any, source: str) -> None:
        if self.state is FactState.ABSENT:
            self.state, self.value, self.default_source = FactState.VENDOR_DEFAULT, value, source

    def as_dict(self) -> dict[str, Any]:
        evidence = sorted(
            {(e.file, e.line_start, e.line_end, e.mapping_ref): e for e in self.evidence}.values(),
            key=lambda e: (e.file, e.line_start, e.line_end, e.mapping_ref or ""),
        )
        return {
            "value": self.value,
            "state": self.state,
            "evidence": evidence,
            "default_source": self.default_source,
        }


@dataclass(frozen=True, slots=True)
class RefRecord:
    """A ``ref`` effect as it was read: who points at what, and on which line."""

    source: EntityRef
    attribute: str
    target_kind: str
    name: str
    evidence: Evidence
    expand: bool = False
    """The source attribute takes the target's members (``ref`` with ``expand``)."""


@dataclass
class EntityAcc:
    evidence: list[Evidence] = field(default_factory=list)
    facts: dict[str, FactAcc] = field(default_factory=dict)

    def fact(self, attr: str) -> FactAcc:
        return self.facts.setdefault(attr, FactAcc())


class SbmBuilder:
    def __init__(self, device: Device | None = None) -> None:
        self.entities: dict[EntityRef, EntityAcc] = {}
        self.unread: dict[str, list[Evidence]] = {}
        self.known_empty: dict[str, str] = {}
        self.refs: list[RefRecord] = []
        self.blocks: dict[tuple[str, ...], EntityRef] = {}
        """Block path -> the entity its header opened (``("ip access-list standard M",)``)."""
        self.unread_children: dict[EntityRef, list[Evidence]] = {}
        """Lines inside an entity's block that no mapping understood. The resolver won't
        conclude "no entry permits everyone" about an ACL with unread entries."""
        self._device_seed = device or Device()
        dev = self.entity(("Device", "device"))
        for attr, fact in self._device_seed:
            if attr in ("type", "key", "evidence") or fact.state is FactState.ABSENT:
                continue
            dev.facts[attr] = FactAcc(
                fact.state, fact.value, list(fact.evidence), fact.default_source
            )

    def entity(self, ref: EntityRef) -> EntityAcc:
        return self.entities.setdefault(ref, EntityAcc())

    @staticmethod
    def singleton(entity_type: str) -> EntityRef:
        return (entity_type, SINGLETON_KEYS[entity_type])

    def of_type(self, entity_type: str) -> list[EntityRef]:
        return sorted(ref for ref in self.entities if ref[0] == entity_type)

    def mark_unread(self, entity_type: str, ev: Evidence) -> None:
        self.unread.setdefault(entity_type, []).append(ev)

    def build(self) -> SecurityBaselineModel:
        device: Device | None = None
        entities: list[Entity] = []
        for (etype, key), acc in sorted(self.entities.items()):
            cls = ENTITY_TYPES[etype]
            data: dict[str, Any] = {"key": key, "evidence": _dedupe(acc.evidence)}
            data.update({attr: f.as_dict() for attr, f in acc.facts.items()})
            entity = cls.model_validate(data)
            if isinstance(entity, Device):
                device = entity
            else:
                entities.append(entity)
        return SecurityBaselineModel(
            device=device or Device(),
            entities=tuple(entities),  # type: ignore[arg-type]
            known_empty=self.known_empty,
            unread={k: _dedupe(v) for k, v in self.unread.items()},
        )


def _dedupe(evidence: list[Evidence]) -> tuple[Evidence, ...]:
    unique = {(e.file, e.line_start, e.line_end, e.mapping_ref): e for e in evidence}
    return tuple(sorted(unique.values(), key=lambda e: (e.file, e.line_start, e.mapping_ref or "")))

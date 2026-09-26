"""The Security Baseline Model document for one device (PLAN §8)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kasauti.sbm.entities import ENTITY_TYPES, SINGLETON_TYPES, AnyEntity, Device, Entity
from kasauti.sbm.facts import Evidence, Fact

SBM_VERSION = "0.6"
"""Bumped on any schema change; older documents are upgraded by ``kasauti.sbm.migrations``."""

E = TypeVar("E", bound=Entity)

DerivedValue = bool | int | str


class SecurityBaselineModel(BaseModel):
    """All entities and derived facts for one device, in a canonical order.

    Entities are sorted by (type, key) on construction so that serialisation is byte-identical
    for identical input (PLAN §3.1, principle 5).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sbm_version: str = SBM_VERSION
    device: Device = Field(default_factory=Device)
    entities: tuple[AnyEntity, ...] = ()
    derived: dict[str, Fact[DerivedValue]] = Field(default_factory=dict)
    known_empty: dict[str, str] = Field(default_factory=dict)
    """Entity types that are *known* to have no members, and the vendor default that says so
    (``SnmpCommunity`` -> ``cisco_ios_xe/defaults.yaml#no-snmp-communities``). Without an entry,
    "no entities of this type" means "nothing seen", never "none exist" (rule-language §3)."""
    unread: dict[str, tuple[Evidence, ...]] = Field(default_factory=dict)
    """Entity types for which some statements looked relevant but could not be read (a pattern
    whose keywords matched but whose values didn't). Quantifiers over such a type can't claim
    "all" or "none", because an unread entity might be the exception."""

    @model_validator(mode="before")
    @classmethod
    def _canonical_order(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("entities"):
            ents = list(data["entities"])
            data = {**data, "entities": tuple(sorted(ents, key=_sort_key))}
        for name in ("derived", "known_empty", "unread"):
            if isinstance(data, dict) and data.get(name):
                data = {**data, name: dict(sorted(data[name].items()))}
        return data

    @model_validator(mode="after")
    def _unique(self) -> Self:
        if self.sbm_version != SBM_VERSION:
            raise ValueError(
                f"sbm_version {self.sbm_version!r} != {SBM_VERSION!r}; run kasauti.sbm.migrations"
            )
        seen: set[tuple[str, str]] = set()
        for ent in self.entities:
            if ent.type == "Device":
                raise ValueError("the Device entity lives in `device`, not in `entities`")
            ident = (ent.type, ent.key)
            if ident in seen:
                raise ValueError(f"duplicate entity {ent.entity_id}")
            if ent.type in SINGLETON_TYPES and any(t == ent.type for t, _ in seen):
                raise ValueError(f"{ent.type} is a singleton")
            seen.add(ident)
        for name in (*self.known_empty, *self.unread):
            if name not in ENTITY_TYPES or name in SINGLETON_TYPES:
                raise ValueError(f"{name!r} is not a multi-entity type")
        return self

    def of_type(self, cls: type[E]) -> tuple[E, ...]:
        if cls is Device:
            return (self.device,)  # type: ignore[return-value]
        return tuple(e for e in self.entities if isinstance(e, cls))

    def all_entities(self) -> Iterator[Entity]:
        yield self.device
        yield from self.entities

    def canonical_json(self) -> str:
        """The byte-stable serialisation used for golden snapshots and hashing."""
        return self.model_dump_json(indent=2)


def _sort_key(entity: Any) -> tuple[str, str]:
    if isinstance(entity, dict):
        return (str(entity.get("type", "")), str(entity.get("key", "")))
    return (str(entity.type), str(entity.key))

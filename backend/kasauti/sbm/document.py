"""The Security Baseline Model document for one device (PLAN §8)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kasauti.sbm.entities import SINGLETON_TYPES, AnyEntity, Device, Entity
from kasauti.sbm.facts import Fact

SBM_VERSION = "0.1"
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

    @model_validator(mode="before")
    @classmethod
    def _canonical_order(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("entities"):
            ents = list(data["entities"])
            data = {**data, "entities": tuple(sorted(ents, key=_sort_key))}
        if isinstance(data, dict) and data.get("derived"):
            data = {**data, "derived": dict(sorted(data["derived"].items()))}
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

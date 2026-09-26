"""The mapping language, v0 (PLAN §9): how a vendor line becomes an SBM fact.

A mapping says: *in this block context, a statement matching this pattern means this about that
entity*. Six primitives plus ``ref``:

========== ============================================================================
primitive  meaning
========== ============================================================================
entity     the statement opens or names an entity (``line vty 0 4`` -> MgmtSession)
set        a slot's value becomes an attribute (with transforms)
assert     presence of the statement means attribute = constant
members    each item of a list slot joins a set attribute
negation   the vendor's negation form inverts the fact (``no``/``undo``/``unset``/…)
default    what holds when nothing is stated; lives in ``defaults.yaml``, per OS version
ref        the attribute points at another named entity (ACL, address object, group)
========== ============================================================================

The stored form is exactly what the Training Studio writes (PLAN §9.3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from kasauti.packs.versions import validate_range
from kasauti.rules.expr import Scalar, attribute_type
from kasauti.sbm.entities import ENTITY_TYPES, SINGLETON_TYPES

# --- Patterns ---------------------------------------------------------------------------------

SlotType = Literal["INT", "IP", "IFNAME", "STR", "LIST"]
SLOT_TYPES: tuple[SlotType, ...] = ("INT", "IP", "IFNAME", "STR", "LIST")
_SLOT = re.compile(r"^<(INT|IP|IFNAME|STR|LIST)(?::([a-z][a-z0-9_]*))?>$")


@dataclass(frozen=True, slots=True)
class Word:
    text: str


@dataclass(frozen=True, slots=True)
class Slot:
    type: SlotType
    name: str | None


PatternToken = Word | Slot


def parse_pattern(pattern: str) -> tuple[PatternToken, ...]:
    """Split a pattern such as ``set allowaccess <LIST:protocols>`` into tokens.

    Rules: whitespace-separated; ``<TYPE>`` or ``<TYPE:name>`` is a slot; ``LIST`` swallows
    the rest of the line so it must come last; slot names are unique.
    """
    raw = pattern.split()
    if not raw:
        raise ValueError("empty pattern")
    tokens: list[PatternToken] = []
    names: set[str] = set()
    for i, part in enumerate(raw):
        if part.startswith("<"):
            m = _SLOT.match(part)
            if m is None:
                raise ValueError(
                    f"bad slot {part!r}; use <TYPE> or <TYPE:name>, TYPE in {SLOT_TYPES}"
                )
            slot_type: SlotType = m.group(1)  # type: ignore[assignment]
            name = m.group(2)
            if slot_type == "LIST" and i != len(raw) - 1:
                raise ValueError("a LIST slot must be the last token")
            if name is not None:
                if name in names:
                    raise ValueError(f"slot name {name!r} used twice")
                names.add(name)
            tokens.append(Slot(slot_type, name))
        else:
            tokens.append(Word(part))
    return tuple(tokens)


def slot_names(pattern: str) -> frozenset[str]:
    return frozenset(t.name for t in parse_pattern(pattern) if isinstance(t, Slot) and t.name)


def _valid_pattern(value: str) -> str:
    parse_pattern(value)
    return value


Pattern = Annotated[str, AfterValidator(_valid_pattern)]
VersionRangeText = Annotated[str, AfterValidator(validate_range)]
SlotName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
AttrPath = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Za-z]+\.[a-z][a-z0-9_]*$")]
"""``Entity.attribute``, e.g. ``Interface.mgmt_protocols``."""

# --- Transforms (PLAN §9.1) -------------------------------------------------------------------

Unit = Literal["ms", "seconds", "minutes", "hours", "days"]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class UnitTransform(_Strict):
    """Normalise a numeric slot to the SBM's unit (seconds for durations)."""

    unit: Unit


class SplitTransform(_Strict):
    split: str = Field(min_length=1)


Transform = Literal["invert", "lower", "upper"] | UnitTransform | SplitTransform

# --- Effects ----------------------------------------------------------------------------------


class SetEffect(_Strict):
    set: AttrPath
    from_: SlotName | dict[SlotName, int] = Field(alias="from")
    """A slot, or a weighted sum of slots: ``{min: 60, sec: 1}`` turns Cisco
    ``exec-timeout 10 0`` into 600 seconds."""
    map: dict[str, Scalar] | None = None
    """Vendor word -> value. A word missing from the map makes the fact ``unknown`` (we saw
    the line but can't say what it means), unless ``otherwise`` is given."""
    otherwise: Scalar | None = None
    """Value for any word not in ``map`` (``is_well_known``: listed strings -> true, any other
    string -> false)."""
    transform: tuple[Transform, ...] = ()

    @model_validator(mode="after")
    def _otherwise_needs_map(self) -> Self:
        if self.otherwise is not None and self.map is None:
            raise ValueError("`otherwise` only makes sense together with `map`")
        return self

    @property
    def attr(self) -> str:
        return self.set

    def slots(self) -> frozenset[str]:
        return frozenset(self.from_) if isinstance(self.from_, dict) else frozenset({self.from_})


class AssertEffect(_Strict):
    assert_: AttrPath = Field(alias="assert")
    value: Scalar | tuple[Scalar, ...]

    @property
    def attr(self) -> str:
        return self.assert_

    def slots(self) -> frozenset[str]:
        return frozenset()


class MembersEffect(_Strict):
    members: AttrPath
    from_: SlotName = Field(alias="from")
    map: dict[str, str] | None = None
    """Vendor word -> SBM vocabulary (``ping -> icmp``). Unmapped words are kept as-is."""
    transform: tuple[Transform, ...] = ()

    @property
    def attr(self) -> str:
        return self.members

    def slots(self) -> frozenset[str]:
        return frozenset({self.from_})


RefTarget = Literal["acl", "address", "address_group", "service", "service_group", "any_object"]


class RefEffect(_Strict):
    ref: AttrPath
    from_: SlotName = Field(alias="from")
    target: RefTarget

    @property
    def attr(self) -> str:
        return self.ref

    def slots(self) -> frozenset[str]:
        return frozenset({self.from_})


Effect = SetEffect | AssertEffect | MembersEffect | RefEffect

# --- Mapping ----------------------------------------------------------------------------------

SIGNALS = ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "manual")


ORDINAL = "{#}"
"""In an entity key, the 1-based order of this statement among the statements that open
entities with the same type and key template. Used where the natural key is a secret: an SNMP
community is keyed ``community-{#}``, never by the community string."""


class EntitySpec(_Strict):
    type: str
    key: str = Field(min_length=1)
    """Literal key or a template over slots: ``"vty {first}-{last}"``, ``"{ifname}"``,
    ``"community-{#}"``."""

    @field_validator("type")
    @classmethod
    def _known(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError(f"unknown entity type {value!r}")
        return value

    def key_slots(self) -> frozenset[str]:
        return frozenset(re.findall(r"{([a-z][a-z0-9_]*)}", self.key))


class Provenance(_Strict):
    version: int = Field(ge=1)
    proposed_by: str = Field(min_length=1)
    approved_by: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()

    @field_validator("signals")
    @classmethod
    def _signals(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        bad = [s for s in value if s not in SIGNALS]
        if bad:
            raise ValueError(f"unknown signals {bad}; expected any of {SIGNALS}")
        return value


MAPPING_ID = r"^[a-z0-9_]+/[a-z0-9][a-z0-9_\-]*$"


class Mapping(_Strict):
    id: Annotated[str, StringConstraints(pattern=MAPPING_ID)]
    vendor: str
    os_versions: VersionRangeText = "*"
    context: tuple[Pattern, ...] = ()
    """Block path the statement must sit in, matched as a suffix of its path ending at its
    parent. Empty means top level only."""
    entity: EntitySpec | None = None
    match: Pattern
    effect: Effect | tuple[Effect, ...] | None = None
    negation: Pattern | Literal["auto"] | None = "auto"
    """``auto`` derives the negated form from the pack's negation words (``no``, ``undo``…)."""
    provenance: Provenance

    @property
    def effects(self) -> tuple[Effect, ...]:
        if self.effect is None:
            return ()
        return self.effect if isinstance(self.effect, tuple) else (self.effect,)

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.id.split("/", 1)[0] != self.vendor:
            raise ValueError(f"id {self.id!r} must start with the vendor {self.vendor!r}/")
        if self.entity is None and not self.effects:
            raise ValueError("a mapping must open an entity, have an effect, or both")
        available = slot_names(self.match).union(*(slot_names(c) for c in self.context))
        needed: set[str] = set()
        if self.entity is not None:
            if self.entity.key in available:
                raise ValueError(
                    f"entity key {self.entity.key!r} is a slot name; write it as "
                    f"'{{{self.entity.key}}}' (a bare word is a literal key)"
                )
            needed |= self.entity.key_slots()
        for eff in self.effects:
            needed |= eff.slots()
            self._check_effect(eff)
        missing = needed - available
        if missing:
            raise ValueError(f"slots {sorted(missing)} are used but not captured by match/context")
        return self

    def _check_effect(self, eff: Effect) -> None:
        entity_type, attr = eff.attr.split(".", 1)
        kind = attribute_type(entity_type, attr)
        if kind is None or attr == "key":
            raise ValueError(f"{eff.attr}: no such SBM attribute")
        if entity_type not in SINGLETON_TYPES and (
            self.entity is None or self.entity.type != entity_type
        ):
            raise ValueError(f"{eff.attr}: effects on {entity_type} need an `entity:` of that type")
        if isinstance(eff, MembersEffect) and kind != "set":
            raise ValueError(f"{eff.attr}: `members` needs a set-valued attribute")
        if isinstance(eff, SetEffect) and kind == "set":
            raise ValueError(f"{eff.attr}: use `members` for set-valued attributes")
        if isinstance(eff, SetEffect) and isinstance(eff.from_, dict) and kind != "int":
            raise ValueError(f"{eff.attr}: a weighted sum needs an int attribute")
        if isinstance(eff, RefEffect) and kind not in ("str", "set"):
            raise ValueError(f"{eff.attr}: `ref` needs a name- or set-valued attribute")

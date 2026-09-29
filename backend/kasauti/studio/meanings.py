"""Meanings a trainer can pick, and how a picked meaning becomes a mapping (PLAN §11.1 steps 3-4;
TODO M2.64, M2.65).

A meaning (``packs/studio/meanings.yaml``) is a template of the mapping language: the entity a
line opens or sits in, and its effects. The trainer marks which words of the line are values
(slots) and which role each fills, picks from the meaning's choices, and :func:`render` builds
the :class:`~kasauti.mapping.model.Mapping` exactly as the pack will store it. Nothing is written
here; the Studio validates, previews and only then stores it on approval.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from kasauti.mapping.model import SLOT_TYPES, Mapping, SlotType
from kasauti.packs.model import EntryId
from kasauti.sbm.entities import ENTITY_TYPES


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class Role(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    label: str
    types: tuple[SlotType, ...] = Field(min_length=1)
    weight: int | None = None
    """Seconds per unit, for a duration built from several slots (minutes 60, seconds 1)."""
    optional: bool = False


class Many(_Strict):
    many: tuple[str, ...] = Field(min_length=1)


class EntityTemplate(_Strict):
    type: str
    key: str
    key_if_missing: str | None = None
    """The key when an optional role isn't filled (``vty {first}`` for a single line)."""


class Meaning(_Strict):
    id: EntryId
    label: str
    explain: str
    words: tuple[str, ...] = ()
    requires: tuple[tuple[str, ...], ...] = ()
    """Words naming the meaning's subject: a line is only suggested this meaning if it has a
    word of every group. ``version`` alone is no reason to read a line as SSH's. A flat list is
    one group."""
    choose: dict[str, tuple[str, ...] | Many] = Field(default_factory=dict)
    roles: tuple[Role, ...] = ()
    under: str | None = None
    entity: EntityTemplate | None = None
    effects: tuple[dict[str, Any], ...] = ()

    @field_validator("requires", mode="before")
    @classmethod
    def _groups(cls, value: Any) -> Any:
        if isinstance(value, list | tuple) and all(isinstance(v, str) for v in value):
            return (tuple(value),) if value else ()
        return value

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        for t in (self.under, self.entity.type if self.entity else None):
            if t is not None and t not in ENTITY_TYPES:
                raise ValueError(f"{self.id}: unknown entity type {t!r}")
        if self.under and self.entity:
            raise ValueError(f"{self.id}: `under` takes the block's entity; give no `entity`")
        if not self.entity and not self.effects:
            raise ValueError(f"{self.id}: a meaning opens an entity, has effects, or both")
        return self


class MeaningFile(_Strict):
    format_version: Literal[1]
    meanings: tuple[Meaning, ...]


MEANINGS = Path(__file__).resolve().parents[3] / "packs" / "studio" / "meanings.yaml"


@cache
def load_meanings(path: Path = MEANINGS) -> dict[str, Meaning]:
    doc = MeaningFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    ids = [m.id for m in doc.meanings]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate meaning ids")
    return {m.id: m for m in doc.meanings}


# --- what the trainer taught --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Token:
    text: str
    slot: SlotType | None = None
    """None: a literal word. Otherwise the value type the word stands for."""
    role: str | None = None
    """The meaning's role this slot fills (``host``), if any."""


@dataclass(frozen=True, slots=True)
class Block:
    """The approved mapping of the block the line sits in: its pattern becomes the new mapping's
    context and its entity is the one the line's effects apply to."""

    match: str
    entity_type: str
    entity_key: str


class TeachError(ValueError):
    """What the trainer taught can't become a valid mapping. User-safe text."""


_WORD = re.compile(r"^[^<>\[\]\s]+$")


def render(
    meaning: Meaning,
    *,
    pack: str,
    tokens: tuple[Token, ...],
    choices: dict[str, str | tuple[str, ...]],
    block: Block | None,
    proposed_by: str,
    signals: tuple[str, ...] = (),
) -> Mapping:
    """The mapping a meaning and the trainer's choices stand for, validated by the mapping
    language itself. :class:`TeachError` says what is missing or wrong."""
    roles = {r.name: r for r in meaning.roles}
    match, bound = _pattern(tokens, roles, meaning.label)
    missing = [r.label for r in meaning.roles if not r.optional and r.name not in bound]
    if missing:
        raise TeachError(f"mark which word is: {', '.join(missing)}")
    values = _chosen(meaning, choices)
    doc: dict[str, Any] = {
        "vendor": pack,
        "match": match,
        "negation": "auto",
        "provenance": {
            "version": 1,
            "proposed_by": proposed_by,
            "approved_by": [],
            "signals": list(signals),
        },
    }
    doc.update(_entity(meaning, block, bound, values))
    effects = [_effect(e, values, roles, bound) for e in meaning.effects]
    if effects:
        doc["effect"] = effects if len(effects) > 1 else effects[0]
    doc["id"] = f"{pack}/studio-{meaning.id}-{_digest(doc)}"
    try:
        return Mapping.model_validate(doc)
    except ValidationError as err:
        first = err.errors()[0]
        raise TeachError(f"this can't be stored as a mapping: {first['msg']}") from None


def _pattern(
    tokens: tuple[Token, ...], roles: dict[str, Role], label: str
) -> tuple[str, dict[str, Token]]:
    """The mapping's ``match``: literal words as they are, values as typed slots named by the
    role they fill."""
    if not tokens:
        raise TeachError("the line has no words")
    bound: dict[str, Token] = {}
    parts: list[str] = []
    for i, t in enumerate(tokens):
        if t.slot is None:
            if not _WORD.match(t.text):
                raise TeachError(f"word {t.text!r} can't be matched literally; make it a value")
            parts.append(t.text)
            continue
        if t.slot not in SLOT_TYPES:
            raise TeachError(f"unknown value type {t.slot!r}")
        parts.append(_slot(t, roles, label, bound))
        if t.slot == "LIST":
            # "The rest of the line": the words after it are part of the value.
            if any(x.slot not in (None, "LIST") or x.role for x in tokens[i + 1 :]):
                raise TeachError("nothing after a rest-of-line value can be a value itself")
            break
    return " ".join(parts), bound


def _slot(t: Token, roles: dict[str, Role], label: str, bound: dict[str, Token]) -> str:
    if t.role is None:
        return f"<{t.slot}>"
    role = roles.get(t.role)
    if role is None:
        raise TeachError(f"{label} has no role {t.role!r}")
    if t.slot not in role.types:
        raise TeachError(f"{role.label} must be one of {', '.join(role.types)}")
    if t.role in bound:
        raise TeachError(f"{role.label} is marked twice")
    bound[t.role] = t
    return f"<{t.slot}:{t.role}>"


def _chosen(
    meaning: Meaning, choices: dict[str, str | tuple[str, ...]]
) -> dict[str, str | tuple[str, ...]]:
    values: dict[str, str | tuple[str, ...]] = {}
    for name, options in meaning.choose.items():
        many = isinstance(options, Many)
        allowed = options.many if isinstance(options, Many) else options
        picked = choices.get(name)
        items = tuple(picked) if isinstance(picked, (list, tuple)) else (picked,) if picked else ()
        if not items:
            raise TeachError(f"choose the {name}")
        if not many and len(items) != 1:
            raise TeachError(f"choose one {name}")
        bad = [x for x in items if x not in allowed]
        if bad:
            raise TeachError(f"{', '.join(bad)} isn't a {name} Kasauti knows")
        values[name] = items if many else items[0]
    return values


def _entity(
    meaning: Meaning,
    block: Block | None,
    bound: dict[str, Token],
    values: dict[str, str | tuple[str, ...]],
) -> dict[str, Any]:
    """The entity the line opens, or the one of the block it sits in (with that block's line as
    its context)."""
    if meaning.under is not None:
        if block is None or block.entity_type != meaning.under:
            raise TeachError(
                f"{meaning.label} belongs inside a block that opens a {meaning.under}; "
                "teach that block's line first"
            )
        return {
            "context": [block.match],
            "entity": {"type": block.entity_type, "key": block.entity_key},
        }
    if meaning.entity is None:
        return {}
    key = meaning.entity.key
    unfilled = any(f"{{{r.name}}}" in key and r.name not in bound for r in meaning.roles)
    if unfilled and meaning.entity.key_if_missing:
        key = meaning.entity.key_if_missing
    return {"entity": {"type": meaning.entity.type, "key": _fill(key, values)}}


def _fill(text: str, values: dict[str, str | tuple[str, ...]]) -> str:
    for name, value in values.items():
        if isinstance(value, str):
            text = text.replace(f"{{{name}}}", value)
    return text


def _effect(
    template: dict[str, Any],
    values: dict[str, str | tuple[str, ...]],
    roles: dict[str, Role],
    bound: dict[str, Token],
) -> dict[str, Any]:
    out = dict(template)
    if out.get("from") == "weighted":
        weights = {n: r.weight for n, r in roles.items() if r.weight and n in bound}
        if not weights:
            raise TeachError("mark at least one of the duration's values")
        # One value in seconds is read as it is; anything else is a weighted sum in seconds.
        only = next(iter(weights)) if len(weights) == 1 else None
        out["from"] = only if only is not None and weights[only] == 1 else weights
    value = out.get("value")
    if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
        picked = values.get(value[1:-1])
        if picked is None:
            raise TeachError(f"choose the {value[1:-1]}")
        out["value"] = list(picked) if isinstance(picked, tuple) else picked
    return out


def _digest(doc: dict[str, Any]) -> str:
    """Six hex digits of what the mapping reads and writes: the same teaching gets the same id,
    so it can't be stored twice."""
    body = yaml.safe_dump(
        {k: doc.get(k) for k in ("match", "context", "entity", "effect")}, sort_keys=True
    )
    return hashlib.sha256(body.encode()).hexdigest()[:6]


def as_yaml(mapping: Mapping) -> str:
    """The mapping as the pack stores it."""
    data = mapping.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    data.setdefault("negation", "auto")
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)

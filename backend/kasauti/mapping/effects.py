"""What one effect does to one fact, given the captured slots (PLAN §9.1).

Order of operations for a value: slot text -> ``map`` -> ``transform``s in order -> coercion to
the attribute's type. Anything that can't be carried through (a slot's word missing from the
map, ``invert`` on a non-boolean, text where a number is needed) yields ``Unknown``: we saw the
line and can't say what it means, which a rule reports as REVIEW rather than guessing. A value
rendered from a ``template`` is built by the mapping itself, so the map only renames the values
it lists (``ip-proto-0 -> ip``) and keeps the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kasauti.mapping.addressing import to_cidr
from kasauti.mapping.match import Captures
from kasauti.mapping.model import (
    AssertEffect,
    Effect,
    MembersEffect,
    PrefixTransform,
    PrependTransform,
    RefEffect,
    SetEffect,
    SplitTransform,
    Transform,
    UnitTransform,
    UnknownEffect,
    template_slots,
)
from kasauti.rules.expr import Type

_SECONDS = {"ms": 0.001, "seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}


@dataclass(frozen=True, slots=True)
class SetValue:
    value: Any


@dataclass(frozen=True, slots=True)
class AddItems:
    items: frozenset[str]


@dataclass(frozen=True, slots=True)
class RemoveItems:
    items: frozenset[str]


@dataclass(frozen=True, slots=True)
class Clear:
    """Back to absent (a negated ``set``), so the version-scoped default can apply."""


@dataclass(frozen=True, slots=True)
class Unknown:
    why: str


Outcome = SetValue | AddItems | RemoveItems | Clear | Unknown


class _UnreadableError(ValueError):
    pass


def evaluate(effect: Effect, caps: Captures, kind: Type, *, negated: bool) -> Outcome:
    try:
        match effect:
            case AssertEffect():
                return _assert(effect, kind, negated=negated)
            case SetEffect():
                return Clear() if negated else SetValue(_coerce(_set_value(effect, caps), kind))
            case MembersEffect():
                return _members(effect, caps, negated=negated)
            case RefEffect():
                return _ref(effect, caps, kind, negated=negated)
            case UnknownEffect():
                return Clear() if negated else Unknown(effect.why)
    except _UnreadableError as err:
        return Unknown(str(err))
    raise AssertionError(f"unhandled effect {effect!r}")  # pragma: no cover


def _assert(effect: AssertEffect, kind: Type, *, negated: bool) -> Outcome:
    value = effect.value
    if kind == "set":
        items = frozenset(str(v) for v in (value if isinstance(value, tuple) else (value,)))
        return RemoveItems(items) if negated else SetValue(items)
    if negated:
        return SetValue(not value) if isinstance(value, bool) else Clear()
    return SetValue(_coerce(value, kind))


def _set_value(effect: SetEffect, caps: Captures) -> Any:
    value: Any
    if effect.template is not None:
        value = _render(effect.template, caps)
    elif isinstance(effect.from_, dict):
        total = 0
        for slot, weight in effect.from_.items():
            part = caps.get(slot)
            if not isinstance(part, int):
                raise _UnreadableError(f"slot {slot!r} is not a number")
            total += part * weight
        value = total
    else:
        value = _slot(caps, str(effect.from_))
    if effect.map is not None and effect.template is not None:
        value = effect.map.get(str(value), value)  # a rendered value: unmapped ones are kept
    elif effect.map is not None:
        word = (
            str(caps.get(f"_raw:{effect.from_}", value))
            if isinstance(effect.from_, str)
            else str(value)
        )
        if word in effect.map:
            value = effect.map[word]
        elif effect.otherwise is not None:
            value = effect.otherwise
        else:
            raise _UnreadableError(f"{word!r} is not a value this mapping knows")
    for t in effect.transform:
        value = _transform(t, value)
    return value


def _members(effect: MembersEffect, caps: Captures, *, negated: bool) -> Outcome:
    if effect.template is not None:
        if negated and not template_slots(effect.template) <= caps.keys():
            return SetValue(frozenset())  # Cisco `no ip address`: explicitly none
        text = _render(effect.template, caps)
        item: Any = str(effect.map.get(text, text)) if effect.map else text
        for t in effect.transform:
            item = _transform(t, item)
        rendered = frozenset({str(item)})
        return RemoveItems(rendered) if negated else AddItems(rendered)
    if effect.from_ not in caps:
        if negated:
            return SetValue(frozenset())  # `unset allowaccess`: explicitly none
        raise _UnreadableError(f"slot {effect.from_!r} not captured")
    raw = caps[effect.from_]
    items: list[Any] = list(raw) if isinstance(raw, tuple) else [raw]
    for t in effect.transform:
        items = [out for item in items for out in _as_list(_transform(t, item))]
    mapped = frozenset(str(effect.map.get(str(i), i)) if effect.map else str(i) for i in items)
    return RemoveItems(mapped) if negated else AddItems(mapped)


def _ref(effect: RefEffect, caps: Captures, kind: Type, *, negated: bool) -> Outcome:
    if negated:
        return Clear()
    name = str(_slot(caps, effect.from_))
    return AddItems(frozenset({name})) if kind == "set" else SetValue(name)


def _render(template: str, caps: Captures) -> str:
    names = template_slots(template)
    missing = sorted(n for n in names if n not in caps)
    if missing:
        raise _UnreadableError(f"slots {missing} not captured")
    return template.format(**{n: _text(caps[n]) for n in names})


def _text(value: Any) -> str:
    return " ".join(value) if isinstance(value, tuple) else str(value)


def _slot(caps: Captures, name: str) -> Any:
    if name not in caps:
        raise _UnreadableError(f"slot {name!r} not captured")
    return caps[name]


def _transform(t: Transform, value: Any) -> Any:
    if t == "invert":
        if not isinstance(value, bool):
            raise _UnreadableError(f"cannot invert {value!r}")
        return not value
    if t == "lower":
        return str(value).lower()
    if t == "upper":
        return str(value).upper()
    if t == "cidr":
        try:
            return to_cidr(str(value))
        except ValueError as exc:
            raise _UnreadableError(str(exc)) from exc
    if isinstance(t, UnitTransform):
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise _UnreadableError(f"{value!r} is not a duration")
        return round(value * _SECONDS[t.unit])
    if isinstance(t, SplitTransform):
        return tuple(p for p in str(value).split(t.split) if p)
    if isinstance(t, PrependTransform):
        return f"{t.prepend}{value}"
    if isinstance(t, PrefixTransform):
        text = str(value)
        hits = [k for k in t.prefix if text.startswith(k)]
        if not hits:
            raise _UnreadableError("value doesn't start with a known prefix")
        return t.prefix[max(hits, key=len)]
    raise AssertionError(f"unhandled transform {t!r}")  # pragma: no cover


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, tuple) else [value]


def _coerce(value: Any, kind: Type) -> Any:
    match kind:
        case "bool":
            if isinstance(value, bool):
                return value
        case "int":
            if isinstance(value, int) and not isinstance(value, bool):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        case "str":
            if isinstance(value, str):
                return value
            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)
        case "set":
            if isinstance(value, tuple | frozenset):
                return frozenset(str(v) for v in value)
            if isinstance(value, str | int) and not isinstance(value, bool):
                return frozenset({str(value)})  # `set` + template: the set is exactly this item
    raise _UnreadableError(f"{value!r} does not fit a {kind} attribute")

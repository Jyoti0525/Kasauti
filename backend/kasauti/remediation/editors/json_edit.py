"""JSON/YAML family (AWS VPC exports): the commands are API calls (the AWS CLI), not lines of the
export, so each recipe also states the export edits its commands make (``edits``). They are
applied to a copy of the export, which is re-audited; the rollback is written in the recipe.

A path is keys joined by ``.``. ``Name{Key=value,Other=value}`` is the item of list ``Name``
holding those fields and ``Name[2]`` its third item. ``where`` keys may be dotted
(``IpRanges.CidrIp``): any item of a list on the way matches.
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from kasauti.packs.model import JsonEdit, Session
from kasauti.remediation.editors import Applied, Change, EditError

_SEGMENT = re.compile(r"^([^{}\[\]]+)(?:\{([^}]*)\}|\[(\d+)\])?$")


def _load(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as err:
            raise EditError(f"the export can't be read: {err}") from None


def _walk(doc: Any, at: str) -> tuple[Any, str]:
    """The object that holds the last key of ``at``, and that key."""
    node = doc
    segments = at.split(".")
    for seg in segments[:-1]:
        node = _segment(node, seg)
    last = _SEGMENT.match(segments[-1])
    if last is None or last.group(2) is not None or last.group(3) is not None:
        raise EditError(f"{at!r}: the last step must be a plain key")
    return node, last.group(1)


def _segment(node: Any, seg: str) -> Any:
    m = _SEGMENT.match(seg)
    if m is None or not isinstance(node, dict) or m.group(1) not in node:
        raise EditError(f"{seg!r} isn't in the export")
    value = node[m.group(1)]
    if m.group(3) is not None:
        index = int(m.group(3))
        if not isinstance(value, list) or index >= len(value):
            raise EditError(f"{seg!r}: there is no such item")
        return value[index]
    if m.group(2) is None:
        return value
    want = dict(pair.split("=", 1) for pair in m.group(2).split(",") if "=" in pair)
    for item in value if isinstance(value, list) else ():
        if isinstance(item, dict) and all(_text(item.get(k)) == v for k, v in want.items()):
            return item
    raise EditError(f"no {m.group(1)} item with {m.group(2)}")


def _text(value: object) -> str:
    """A value as the export writes it: ``false``, not Python's ``False``."""
    return json.dumps(value) if isinstance(value, bool) or value is None else str(value)


def _holds(item: Any, key: str, want: object) -> bool:
    head, _, rest = key.partition(".")
    if not isinstance(item, dict) or head not in item:
        return False
    value = item[head]
    if rest:
        values = value if isinstance(value, list) else [value]
        return any(_holds(v, rest, want) for v in values)
    return bool(value == want or _text(value) == _text(want))


def _apply(doc: Any, edit: JsonEdit) -> tuple[list[str], list[str]]:
    """Apply one edit; what it took out and what it put in, as text for the record."""
    holder, key = _walk(doc, edit.at)
    if not isinstance(holder, dict):
        raise EditError(f"{edit.at!r} doesn't lead to an object")
    if edit.op == "set":
        had, old = key in holder, holder.get(key)
        holder[key] = edit.value
        was = [f"{edit.at} = {json.dumps(old)}"] if had else []
        return was, [f"{edit.at} = {json.dumps(edit.value)}"]
    items = holder.setdefault(key, []) if edit.op == "append" else holder.get(key)
    if not isinstance(items, list):
        raise EditError(f"{edit.at!r} isn't a list")
    if edit.op == "append":
        items.append(edit.value)
        return [], [f"{edit.at} += {json.dumps(edit.value, sort_keys=True)}"]
    gone = [i for i in items if all(_holds(i, k, v) for k, v in edit.where.items())]
    holder[key] = [i for i in items if i not in gone]
    return [f"{edit.at}: {json.dumps(g, sort_keys=True)}" for g in gone], []


class JsonEditor:
    def apply(self, text: str, change: Change, session: Session) -> Applied:
        if not change.edits:
            raise EditError("this platform's fixes need `edits` in their recipe")
        doc = _load(text)
        applied = Applied(text=text)
        for edit in change.edits:
            removed, added = _apply(doc, edit)
            if edit.op == "remove" and not removed:
                raise EditError(f"nothing under {edit.at} matches {edit.where}")
            applied.removed += [("", r) for r in removed]
            applied.added += [("", a) for a in added]
            applied.paths.append(edit.at)
        applied.text = json.dumps(doc, indent=2) + "\n"
        return applied

    def rollback(self, applied: Applied, session: Session) -> tuple[str, ...]:
        return ()  # the recipe writes it: API calls can't be derived from the export

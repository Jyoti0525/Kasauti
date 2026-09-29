"""XML family (PAN-OS): configure-mode ``set`` and ``delete`` commands applied to the XML
configuration they address, as the firewall's candidate configuration takes them.

A command's words are a path into the XML: an element per word, and for a list (elements
holding ``<entry name="…">``) the next word is an entry's name. The last word of ``set`` is the
value; ``[ a b ]`` is a member list. The first word says where the path starts: ``mgt-config``
and ``shared`` at ``/config``, ``deviceconfig`` and ``network`` under the device, anything else
(``rulebase``, ``zone`` …) under the first virtual system, as on a single-vsys firewall.
"""

from __future__ import annotations

import shlex
import xml.etree.ElementTree as ET  # nosec B405 - serialising only; parsing goes through defusedxml

import defusedxml.ElementTree as SafeET

from kasauti.packs.model import Session
from kasauti.remediation.editors import Applied, Change, EditError

_ROOT = frozenset({"mgt-config", "shared"})
_DEVICE = frozenset({"deviceconfig", "network"})
LISTS: dict[str, frozenset[str]] = {
    "mgt-config": frozenset({"users"}),
    "shared": frozenset({"authentication-profile", "address", "address-group", "service"}),
    "devices": frozenset({"vsys"}),
    "vsys": frozenset({"zone", "address", "address-group", "service", "service-group"}),
    "security": frozenset({"rules"}),
    "network": frozenset({"virtual-router"}),
    "interface": frozenset({"ethernet"}),
    "layer3": frozenset({"ip"}),
    "profiles": frozenset({"interface-management-profile"}),
    "interface-management-profile": frozenset({"permitted-ip"}),
    "system": frozenset({"permitted-ip", "match-list"}),
    "config": frozenset({"match-list"}),
    "log-settings": frozenset({"syslog"}),
    "syslog": frozenset({"server"}),
    "server-profile": frozenset({"tacplus", "radius", "ldap"}),
    "tacplus": frozenset({"server"}),
    "radius": frozenset({"server"}),
}
"""Which elements are lists of ``<entry name="…">``, by the element they sit in (PAN-OS XML
API reference): a TACACS+ server's ``address`` is a value where a vsys's ``address`` is a list,
and ``method tacplus`` is a container where ``server-profile tacplus`` is a list. An entry
counts as its list: a vsys entry's children are looked up under ``vsys``. An element that
already holds entries is a list wherever it is."""
MEMBERS = frozenset(
    {"from", "to", "source", "destination", "application", "service", "send-syslog", "allow-list"}
)
"""Elements that hold ``<member>`` values: one value set on them is a one-member list."""
CHOICES = frozenset({"authentication-type", "algorithm", "version"})
"""Elements holding one of several alternatives (``none`` or ``symmetric-key``): setting one
replaces the others, as the CLI does."""


def _name(stack: list[ET.Element], i: int) -> str:
    """What ``stack[i]`` is called for :data:`LISTS`: an entry goes by the list it is in."""
    el = stack[i]
    return stack[i - 1].tag if el.tag == "entry" and i > 0 else el.tag


def _is_list(stack: list[ET.Element]) -> bool:
    el = stack[-1]
    kids = list(el)
    if kids:
        return all(k.tag == "entry" for k in kids)
    return len(stack) > 1 and el.tag in LISTS.get(_name(stack, len(stack) - 2), frozenset())


def _find(el: ET.Element, word: str) -> ET.Element | None:
    for kid in el:
        if kid.tag == "entry" and kid.get("name") == word:
            return kid
    for kid in el:
        if kid.tag == word:
            return kid
    return None


def _create(stack: list[ET.Element], word: str) -> ET.Element:
    el = stack[-1]
    if _is_list(stack):
        return ET.SubElement(el, "entry", {"name": word})
    if el.tag in CHOICES:
        for kid in list(el):
            el.remove(kid)
    return ET.SubElement(el, word)


def _start(root: ET.Element, first: str) -> list[ET.Element] | None:
    """Where a command's path starts, with the elements above it (to tell lists apart)."""
    if first in _ROOT:
        return [root]
    devices = root.find("devices")
    device = None if devices is None else devices.find("entry")
    if devices is None or device is None:
        return None
    if first in _DEVICE or first == "vsys":
        return [root, devices, device]
    vsys = device.find("vsys")
    first_vsys = None if vsys is None else vsys.find("entry")
    if vsys is None or first_vsys is None:
        return None
    return [root, devices, device, vsys, first_vsys]


def _walk(root: ET.Element, path: list[str]) -> tuple[list[ET.Element], list[str]]:
    """The elements down ``path``, created where missing, and the paths it had to create."""
    stack = _start(root, path[0])
    if stack is None:
        raise EditError(f"{' '.join(path)}: the configuration has no device or vsys entry")
    made: list[str] = []
    for i, word in enumerate(path):
        nxt = _find(stack[-1], word)
        if nxt is None:
            nxt = _create(stack, word)
            made.append(" ".join(path[: i + 1]))
        stack.append(nxt)
    return stack, made


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError as err:
        raise EditError(f"{line!r}: {err}") from None


def _flatten(el: ET.Element, path: list[str]) -> list[str]:
    """An element's leaves as ``set`` commands, to put back what a ``delete`` removed."""
    kids = list(el)
    if not kids:
        return [f"set {' '.join(path)} {_quote(el.text or '')}".rstrip()]
    if all(k.tag == "member" for k in kids):
        return [f"set {' '.join(path)} [ {' '.join(_quote(k.text or '') for k in kids)} ]"]
    out: list[str] = []
    for kid in kids:
        name = kid.get("name") if kid.tag == "entry" else kid.tag
        out += _flatten(kid, [*path, name or kid.tag])
    return out


def _quote(value: str) -> str:
    return f'"{value}"' if (" " in value or not value) else value


class XmlSetEditor:
    def apply(self, text: str, change: Change, session: Session) -> Applied:
        try:
            root = SafeET.fromstring(text)
        except SafeET.ParseError as err:
            raise EditError(f"the XML can't be read: {err}") from None
        applied = Applied(text=text)
        for typed in change.stored:
            words = _words(typed)
            if not words or words[0] in ("configure", "commit", "exit"):
                continue
            verb, path = words[0], words[1:]
            if verb not in ("set", "delete") or not path:
                raise EditError(f"{typed!r} is not a set or delete command")
            if verb == "delete":
                self._delete(root, path, applied)
            else:
                self._set(root, path, applied)
        # Written as the firewall exports it, one element per line, so each statement of the
        # changed copy keeps a line of its own.
        ET.indent(root, space="  ")
        applied.text = '<?xml version="1.0"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
        return applied

    def _set(self, root: ET.Element, words: list[str], applied: Applied) -> None:
        members: list[str] | None = None
        if "[" in words and words[-1] == "]":
            at = words.index("[")
            members, words = words[at + 1 : -1], words[:at]
            path, value = words, None
        else:
            path, value = words[:-1], words[-1]
        stack, made = _walk(root, path)
        el = stack[-1]
        where = " ".join(path)
        if members is None and value is not None and _is_list(stack):
            # `set deviceconfig system permitted-ip 10.0.0.0/24`: the value names an entry.
            if _find(el, value) is None:
                _create(stack, value)
                applied.created.append(f"{where} {value}")
                applied.added.append(("", f"set {where} {_quote(value)}"))
            applied.paths.append(where)
            return
        if members is None and el.tag in MEMBERS:
            members = [value or ""]
        old = _flatten(el, path) if (len(el) or el.text) and not made else []
        for kid in list(el):
            el.remove(kid)
        if members is not None:
            for m in members:
                ET.SubElement(el, "member").text = m
            new = f"set {where} [ {' '.join(members)} ]"
        else:
            el.text = value
            new = f"set {where} {_quote(value or '')}"
        if made:
            applied.created.append(made[0])
        if old and old != [new]:
            applied.replaced += [("", o, new) for o in old]
            applied.removed += [("", o) for o in old]
        if old != [new]:
            applied.added.append(("", new))
        applied.paths.append(" ".join(path[: max(1, len(path) - (0 if members else 1))]))

    def _delete(self, root: ET.Element, path: list[str], applied: Applied) -> None:
        stack = _start(root, path[0])
        if stack is None:
            return
        parent, el = None, stack[-1]
        for word in path:
            found = _find(el, word)
            if found is None:
                return  # already absent: nothing to delete
            parent, el = el, found
        if parent is None:
            return
        applied.removed += [("", line) for line in _flatten(el, path)]
        parent.remove(el)
        applied.paths.append(" ".join(path[:-1]) or path[0])

    def rollback(self, applied: Applied, session: Session) -> tuple[str, ...]:
        out: list[str] = list(session.enter)
        replaced_old = {o for _, o, _ in applied.replaced}
        out += [f"delete {p}" for p in applied.created]
        out += [old for _, old, _ in applied.replaced]
        out += [line for _, line in applied.removed if line not in replaced_old]
        out += list(session.save)
        return tuple(out)

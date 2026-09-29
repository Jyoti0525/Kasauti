"""Indent family (Cisco IOS/IOS XE/NX-OS, Arista EOS): configuration-mode commands merged into a
running configuration as the device would merge them.

A top-level line followed by indented lines in the change enters that block (``line vty 0 4``);
``exit`` leaves it, and ``configure terminal`` and ``end`` frame the session. For each command:

* ``no X`` removes the lines ``X`` and ``X …`` in its block (a whole block, at the top level),
  then stays as a line if the pack's session lists it in ``kept_negations`` (a feature that is
  on by default, turned off: ``no ip http server``);
* any other command overwrites the lines it ``replaces`` (``exec-timeout …``) and its own
  ``no`` form, and is added unless it is already there.

A ``banner`` and its body (``^C`` delimited, or up to ``EOF`` on EOS) are one unit.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from kasauti.packs.model import Session
from kasauti.remediation.editors import Applied, Change, EditError

_FRAME = frozenset({"configure terminal", "conf t", "configure", "end"})
_BANNER = re.compile(r"^banner\s+(\S+)")


@dataclass
class _Node:
    header: str
    children: list[str] = field(default_factory=list)
    """Each child line without the block's own indent, so a sub-mode keeps its depth
    (``archive`` → ``log config`` → `` logging enable``)."""
    body: list[str] | None = None
    """A banner's lines, verbatim, its closing delimiter included."""
    indent: str = " "
    gone: bool = False
    """Taken out by the change, so a lookup by its header no longer finds it."""


def _key(line: str) -> str:
    return " ".join(line.split())


def _matches(line: str, target: str) -> bool:
    k, t = _key(line), _key(target)
    return k == t or k.startswith(t + " ")


def _parse(text: str) -> list[_Node]:
    nodes: list[_Node] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line[:1] in (" ", "\t") and nodes and nodes[-1].body is None and line.strip():
            node = nodes[-1]
            if not node.children:
                node.indent = line[: len(line) - len(line.lstrip())]
            rest = line.rstrip()
            node.children.append(
                rest[len(node.indent) :] if rest.startswith(node.indent) else rest.strip()
            )
            i += 1
            continue
        node = _Node(line.rstrip())
        nodes.append(node)
        i += 1
        if _BANNER.match(line.strip()):
            node.body, i = _banner_body(lines, i, line.strip())
    return nodes


def _delimiter(header: str) -> str | None:
    """``banner login ^C`` → ``^C``; EOS's ``banner login`` has none (its body ends at EOF)."""
    words = header.split()
    return words[2][:2] if len(words) > 2 else None


def _banner_body(lines: list[str], i: int, header: str) -> tuple[list[str], int]:
    delim = _delimiter(header)
    if delim is not None and header.split(None, 2)[2][len(delim) :].find(delim) >= 0:
        return [], i  # the whole banner on one line
    end = delim or "EOF"
    body: list[str] = []
    while i < len(lines):
        body.append(lines[i])
        i += 1
        if end in body[-1]:
            break
    return body, i


def _render(nodes: list[_Node]) -> str:
    out: list[str] = []
    for n in nodes:
        out.append(n.header)
        if n.body is not None:
            out.extend(n.body)
        out.extend(n.indent + c for c in n.children)
    return "\n".join(out) + "\n"


class IndentEditor:
    def apply(self, text: str, change: Change, session: Session) -> Applied:
        nodes = _parse(text)
        index: dict[str, _Node] = {}
        for n in nodes:
            if n.body is None:
                index.setdefault(_key(n.header), n)
        applied = Applied(text=text)
        script = list(zip(change.lines, change.stored, strict=True))
        block: _Node | None = None
        i = 0
        while i < len(script):
            typed, stored = script[i]
            word = _key(typed)
            if word and not _key(stored):
                i += 1  # typed, and kept nowhere in the configuration (an SNMPv3 user)
                continue
            if not word or word in _FRAME or word == "exit":
                block = None
                i += 1
                continue
            nested = typed[:1] in (" ", "\t")
            if not nested and _BANNER.match(word):
                end = _delimiter(word) or "EOF"
                body: list[str] = []
                i += 1
                while i < len(script):
                    body.append(script[i][1])
                    i += 1
                    if end in body[-1]:
                        break
                self._banner(nodes, _key(stored), body, applied)
                block = None
                continue
            if not nested and i + 1 < len(script) and script[i + 1][0][:1] in (" ", "\t"):
                block = self._enter(nodes, _key(stored), applied, index)
                i += 1
                continue
            if nested and block is None:
                raise EditError(f"{typed.strip()!r} is indented but follows no block")
            self._command(
                nodes,
                block if nested else None,
                _key(stored),
                depth=len(stored) - len(stored.lstrip(" ")),
                change=change,
                session=session,
                applied=applied,
            )
            if not nested:
                block = None
            i += 1
        applied.text = _render(nodes)
        return applied

    def rollback(self, applied: Applied, session: Session) -> tuple[str, ...]:
        """Undo in reverse: overwritten settings written back, added lines negated, removed
        lines restored, created blocks removed whole."""
        blocks: dict[str, list[str]] = {}
        replaced_new = {(b, new) for b, _, new in applied.replaced}
        replaced_old = {(b, old) for b, old, _ in applied.replaced}
        for blk, line in reversed(applied.added):
            if blk in applied.created or (not blk and line in applied.created):
                continue
            if (blk, line) in replaced_new:
                continue
            if not blk and line.startswith("banner "):
                blocks.setdefault("", []).append(f"no banner {line.split()[1]}")
            elif line.startswith("no "):
                blocks.setdefault(blk, []).append(line[3:])
            else:
                blocks.setdefault(blk, []).append(f"no {line}")
        for blk, old, _ in applied.replaced:
            blocks.setdefault(blk, []).append(old)
        for blk, line in applied.removed:
            if (blk, line) not in replaced_old and blk not in applied.created:
                blocks.setdefault(blk, []).append(line)
        out: list[str] = list(session.enter)
        out.extend(dict.fromkeys(blocks.pop("", [])))
        for blk, cmds in blocks.items():
            out.append(blk)
            out.extend(f" {c}" for c in dict.fromkeys(cmds))
            out.append(" exit")
        out.extend(f"no {b}" for b in applied.created)
        out.extend(session.exit)
        return tuple(out)

    # -- internals ----------------------------------------------------------------------------

    def _enter(
        self, nodes: list[_Node], header: str, applied: Applied, index: dict[str, _Node]
    ) -> _Node:
        """The block ``header`` opens, found through ``index`` (a large configuration has
        thousands of blocks, and a fix can enter hundreds), or created before ``end``."""
        if header not in applied.paths:
            applied.paths.append(header)
        found = index.get(header)
        if found is not None and not found.gone:
            return found
        node = _Node(header, indent=_indent_of(nodes))
        _insert(nodes, node)
        index[header] = node
        applied.created.append(header)
        return node

    def _banner(self, nodes: list[_Node], header: str, body: list[str], applied: Applied) -> None:
        kind = header.split()[1]
        for n in list(nodes):
            m = _BANNER.match(_key(n.header))
            if n.body is not None and m and m.group(1) == kind:
                applied.removed.append(("", _key(n.header)))
                nodes.remove(n)
        _insert(nodes, _Node(header, body=body))
        applied.added.append(("", header))
        applied.paths.append(f"banner {kind}")

    def _command(
        self,
        nodes: list[_Node],
        block: _Node | None,
        line: str,
        *,
        depth: int,
        change: Change,
        session: Session,
        applied: Applied,
    ) -> None:
        """``depth``: how many spaces the change indents the line, one per sub-mode level."""
        blk = "" if block is None else _key(block.header)
        if not blk:
            applied.paths.append(" ".join(line.removeprefix("no ").split()[:2]))
        if line.startswith("no "):
            target = line[3:]
            applied.removed += self._remove(nodes, block, lambda s: _matches(s, target))
            if any(_matches(line, k) for k in session.kept_negations):
                self._add(nodes, block, line, applied, blk, depth)
            return
        prefixes = [p for p in change.replaces if _matches(line, p)]
        overwritten = self._remove(
            nodes,
            block,
            lambda s: _key(s) != line and any(_matches(s, p) for p in prefixes),
        )
        applied.removed += self._remove(nodes, block, lambda s: _key(s) == f"no {line}")
        applied.removed += overwritten
        applied.replaced += [(b, old, line) for b, old in overwritten if b == blk]
        self._add(nodes, block, line, applied, blk, depth)

    def _remove(
        self, nodes: list[_Node], block: _Node | None, hit: Callable[[str], bool]
    ) -> list[tuple[str, str]]:
        """``(block, line)`` of what was taken out. A top-level block goes whole: its children
        are listed under it, so a rollback rebuilds it."""
        if block is not None:
            blk = _key(block.header)
            removed = [(blk, c) for c in block.children if hit(c)]
            block.children[:] = [c for c in block.children if not hit(c)]
            return removed
        out: list[tuple[str, str]] = []
        for n in list(nodes):
            if n.body is None and hit(n.header):
                header = _key(n.header)
                out += [(header, c) for c in n.children] if n.children else [("", header)]
                n.gone = True
                nodes.remove(n)
        return out

    def _add(  # noqa: PLR0917
        self,
        nodes: list[_Node],
        block: _Node | None,
        line: str,
        applied: Applied,
        blk: str,
        depth: int = 0,
    ) -> None:
        if block is not None:
            if all(_key(c) != line for c in block.children):
                block.children.append(block.indent * max(0, depth - 1) + line)
                applied.added.append((blk, line))
        elif all(_key(n.header) != line for n in nodes):
            _insert(nodes, _Node(line))
            applied.added.append(("", line))


def _indent_of(nodes: list[_Node]) -> str:
    for n in nodes:
        if n.children:
            return n.indent
    return " "


def _insert(nodes: list[_Node], node: _Node) -> None:
    """Before the closing ``end``, so the file still reads as one configuration."""
    at = len(nodes)
    for i in range(len(nodes) - 1, -1, -1):
        if _key(nodes[i].header) == "end":
            at = i
            break
    nodes.insert(at, node)

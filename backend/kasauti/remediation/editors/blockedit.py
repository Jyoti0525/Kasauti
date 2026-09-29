"""Block-edit family (FortiOS): ``config``/``edit``/``set``/``unset``/``next``/``end`` scripts
merged into a configuration as the device merges them. ``set k …`` overwrites ``k`` in its
block, ``unset k`` removes it, ``delete N`` removes the entry ``N`` of the ``config`` it is in.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kasauti.packs.model import Session
from kasauti.remediation.editors import Applied, Change, EditError


@dataclass
class _Block:
    kind: str
    """``config`` or ``edit``."""
    name: str
    items: list[_Block | str] = field(default_factory=list)
    """Child blocks and ``set …`` lines, in order."""


def _unquote(name: str) -> str:
    return name.strip().strip('"')


def _parse(text: str) -> tuple[list[str], _Block]:
    head: list[str] = []
    root = _Block("root", "")
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") and len(stack) == 1:
            head.append(raw)
            continue
        word, _, rest = line.partition(" ")
        if word in ("config", "edit"):
            blk = _Block(word, rest.strip())
            stack[-1].items.append(blk)
            stack.append(blk)
        elif word in ("end", "next"):
            if len(stack) > 1:
                stack.pop()
        else:
            stack[-1].items.append(line)
    return head, root


def _render(head: list[str], root: _Block) -> str:
    out = list(head)

    def walk(blk: _Block, depth: int) -> None:
        pad = "    " * depth
        for item in blk.items:
            if isinstance(item, str):
                out.append(pad + item)
                continue
            out.append(f"{pad}{item.kind} {item.name}")
            walk(item, depth + 1)
            out.append(pad + ("end" if item.kind == "config" else "next"))

    walk(root, 0)
    return "\n".join(out) + "\n"


def _key(line: str) -> str:
    words = line.split()
    return " ".join(words[:2])


def _child(parent: _Block, kind: str, name: str) -> _Block | None:
    for item in parent.items:
        if isinstance(item, _Block) and item.kind == kind and _unquote(item.name) == _unquote(name):
            return item
    return None


class BlockEditEditor:
    def apply(self, text: str, change: Change, session: Session) -> Applied:
        head, root = _parse(text)
        applied = Applied(text=text)
        stack: list[_Block] = [root]
        names: list[str] = []
        for typed in change.stored:
            line = typed.strip()
            if not line:
                continue
            word, _, rest = line.partition(" ")
            where = " / ".join(names)
            if word in ("config", "edit"):
                found = _child(stack[-1], word, rest)
                if found is None:
                    found = _Block(word, rest.strip())
                    stack[-1].items.append(found)
                    applied.created.append(" / ".join([*names, f"{word} {rest.strip()}"]))
                stack.append(found)
                names.append(f"{word} {rest.strip()}")
                if word == "config" or len(names) <= 2:
                    applied.paths.append(_show_path(names))
            elif word in ("next", "end"):
                if len(stack) == 1:
                    raise EditError(f"{line!r} closes a block that isn't open")
                stack.pop()
                names.pop()
            elif word in ("set", "unset", "delete"):
                _setting(stack[-1], word, line, where, applied)
            else:
                raise EditError(f"{line!r} isn't a FortiOS configuration command")
        if len(stack) > 1:
            raise EditError("the change leaves a block open (a missing next or end)")
        applied.text = _render(head, root)
        return applied

    def rollback(self, applied: Applied, session: Session) -> tuple[str, ...]:
        by_block: dict[str, list[str]] = {}
        replaced_new = {(b, n) for b, _, n in applied.replaced}
        replaced_old = {(b, o) for b, o, _ in applied.replaced}
        # An entry the change created is deleted whole (below); a `config` block can't be,
        # so each setting the change put in it is unset.
        deleted = {c for c in applied.created if c.split(" / ")[-1].startswith("edit ")}
        for blk, line in applied.added:
            inside_new_entry = any(blk == d or blk.startswith(d + " / ") for d in deleted)
            if (blk, line) not in replaced_new and not inside_new_entry:
                by_block.setdefault(blk, []).append("unset " + line.split()[1])
        for blk, old, _ in applied.replaced:
            by_block.setdefault(blk, []).append(old)
        for blk, line in applied.removed:
            if (blk, line) not in replaced_old:
                by_block.setdefault(blk, []).append(line)
        out: list[str] = list(session.enter)
        for blk, cmds in by_block.items():
            out += _wrap(blk.split(" / ") if blk else [], cmds)
        for created in applied.created:
            parts = created.split(" / ")
            if parts[-1].startswith("edit "):
                out += _wrap(parts[:-1], [f"delete {parts[-1][5:]}"])
        out += list(session.exit)
        return tuple(out)


def _setting(blk: _Block, word: str, line: str, where: str, applied: Applied) -> None:
    """``set`` overwrites its key in the block, ``unset`` removes it, ``delete N`` removes the
    entry ``N`` of the ``config`` block."""
    rest = line.partition(" ")[2]
    if word == "delete":
        gone = _child(blk, "edit", rest)
        if gone is not None:
            blk.items.remove(gone)
            inner = f"{where} / edit {gone.name}"
            applied.removed += [(inner, i) for i in gone.items if isinstance(i, str)]
        return
    key = _key(line) if word == "set" else "set " + rest.split()[0]
    old = [i for i in blk.items if isinstance(i, str) and _key(i) == key]
    blk.items = [i for i in blk.items if i not in old]
    if word == "unset":
        applied.removed += [(where, o) for o in old]
        return
    blk.items.append(line)
    applied.removed += [(where, o) for o in old if o != line]
    applied.replaced += [(where, o, line) for o in old if o != line]
    if not old or old[0] != line:
        applied.added.append((where, line))


def _wrap(names: list[str], cmds: list[str]) -> list[str]:
    out: list[str] = []
    for depth, name in enumerate(names):
        out.append("    " * depth + name)
    out += ["    " * len(names) + c for c in cmds]
    for depth in range(len(names) - 1, -1, -1):
        out.append("    " * depth + ("end" if names[depth].startswith("config") else "next"))
    return out


def _show_path(names: list[str]) -> str:
    """``show system interface wan1``: the config path, and an entry's name where there is one."""
    words: list[str] = []
    for n in names[:2]:
        kind, _, rest = n.partition(" ")
        words.append(_unquote(rest) if kind == "edit" else rest)
    return " ".join(words)

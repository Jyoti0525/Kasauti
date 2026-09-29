"""Set-path families (Junos, VyOS style): ``set`` and ``delete`` commands applied to a
configuration in its ``display set`` form, as the device's candidate configuration takes them.
A brace configuration is written out in that form first (:func:`set_lines`).

``set P`` adds the statement (dropping the statements it ``replaces``: a leaf with a new value);
``delete P`` removes ``set P`` and everything under it.
"""

from __future__ import annotations

from collections.abc import Sequence

from kasauti.packs.model import Session
from kasauti.remediation.editors import Applied, Change, EditError
from kasauti.shape.model import Statement


def set_lines(statements: Sequence[Statement]) -> str:
    """A brace tree as ``show configuration | display set`` prints it: one ``set`` per leaf."""
    headers = {s.path[: i + 1] for s in statements for i in range(len(s.path))}
    out = []
    for s in statements:
        full = (*s.path, s.text)
        if full in headers:
            continue  # a block: its leaves carry it
        out.append("set " + " ".join(full))
    return "\n".join(out) + "\n"


def _words(line: str) -> list[str]:
    return line.split()


def _under(line: str, path: list[str]) -> bool:
    w = _words(line)
    return w[:1] == ["set"] and w[1 : 1 + len(path)] == path


class SetPathEditor:
    def apply(self, text: str, change: Change, session: Session) -> Applied:
        lines = text.splitlines()
        applied = Applied(text=text)
        for typed in change.stored:
            w = _words(typed)
            if not w or w[0] in ("configure", "commit", "exit", "top", "edit"):
                continue
            if w[0] == "delete":
                path = w[1:]
                gone = [ln for ln in lines if _under(ln, path)]
                lines = [ln for ln in lines if not _under(ln, path)]
                applied.removed += [("", " ".join(_words(g))) for g in gone]
                applied.paths.append(" ".join(path[: max(1, min(3, len(path) - 1))]))
                continue
            if w[0] != "set":
                raise EditError(f"{typed!r} is not a set or delete command")
            line = " ".join(w)
            prefixes = [p.split() for p in change.replaces if line.startswith(p + " ") or line == p]
            over = [
                ln
                for ln in lines
                if " ".join(_words(ln)) != line and any(_under(ln, p[1:]) for p in prefixes)
            ]
            lines = [ln for ln in lines if ln not in over]
            applied.removed += [("", " ".join(_words(o))) for o in over]
            applied.replaced += [("", " ".join(_words(o)), line) for o in over]
            if all(" ".join(_words(ln)) != line for ln in lines):
                lines.append(line)
                applied.added.append(("", line))
            applied.paths.append(" ".join(w[1 : 1 + max(1, min(3, len(w) - 2))]))
        applied.text = "\n".join(lines) + "\n"
        return applied

    def rollback(self, applied: Applied, session: Session) -> tuple[str, ...]:
        if session.rollback:
            return session.rollback
        out: list[str] = list(session.enter)
        out += ["delete " + line.removeprefix("set ") for _, line in applied.added]
        out += [line for _, line in applied.removed]
        out += list(session.save)
        return tuple(out)

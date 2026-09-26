"""Line-oriented shape families (PLAN §6.1): set-path, block-edit, path-command and flat.

All four read logical lines: a double-quoted value may span physical lines (FortiOS
certificates and replacement messages), and MikroTik continues a line with a trailing ``\\``.
A statement's ``line_start``/``line_end`` always cover every physical line it came from.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from kasauti.shape.base import ParseError, RawStatement
from kasauti.shape.tokens import split_lines

COMMENTS = ("#",)


def logical_lines(text: str, *, continuation: bool = False) -> Iterator[tuple[int, int, str]]:
    """Yield ``(first line, last line, text)``, joining quoted values and ``\\`` continuations."""
    lines = split_lines(text)
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i]
        while (_open_quote(buf) or (continuation and buf.rstrip().endswith("\\"))) and i + 1 < len(
            lines
        ):
            if continuation and buf.rstrip().endswith("\\") and not _open_quote(buf):
                buf = buf.rstrip()[:-1] + " " + lines[i + 1].lstrip()
            else:
                buf = buf + "\n" + lines[i + 1]
            i += 1
        yield start + 1, i + 1, buf.strip()
        i += 1


def _open_quote(text: str) -> bool:
    return len(re.findall(r'(?<!\\)"', text)) % 2 == 1


# --- set-path: `set …` forms of Junos, VyOS, PAN-OS, Check Point Gaia; Extreme EXOS --------------


def parse_set_path(text: str) -> Iterator[RawStatement]:
    """``set system services telnet`` -> statement ``system services telnet`` (path empty).

    Only the ``set`` verb is dropped. Other verbs (``delete``, ``deactivate``, ``unset``) stay as
    the first word, so a pack lists them as negation words and they invert the fact.
    """
    for start, end, line in logical_lines(text):
        if not line or line.startswith(COMMENTS):
            continue
        verb, _, rest = line.partition(" ")
        if verb == "set" and not rest.strip():
            raise ParseError("'set' with nothing after it", start)
        yield RawStatement((), rest.strip() if verb == "set" else line, start, end)


# --- block-edit: FortiOS `config … / edit … / set … / next / end` -----------------------------


def parse_block_edit(text: str) -> Iterator[RawStatement]:
    stack: list[tuple[str, str, int]] = []  # (kind, header, line)
    for start, end, body in logical_lines(text):
        if not body or body.startswith(COMMENTS):
            continue
        word = body.split(None, 1)[0]
        path = tuple(h for _, h, _ in stack)
        if word == "config":
            yield RawStatement(path, body, start, end)
            stack.append(("config", body, start))
        elif word == "edit":
            if not stack or stack[-1][0] != "config":
                raise ParseError("'edit' outside a 'config' block", start)
            yield RawStatement(path, body, start, end)
            stack.append(("edit", body, start))
        elif body == "next":
            if not stack or stack[-1][0] != "edit":
                raise ParseError("'next' without a matching 'edit'", start)
            stack.pop()
        elif body == "end":
            while stack and stack[-1][0] == "edit":
                stack.pop()  # FortiOS tolerates a missing `next` before `end`
            if not stack:
                raise ParseError("'end' without a matching 'config'", start)
            stack.pop()
        else:
            yield RawStatement(path, body, start, end)
    if stack:
        kind, header, line = stack[-1]
        raise ParseError(f"{kind} block {header!r} is never closed", line)


# --- path-command: MikroTik RouterOS `/ip service` + `set telnet disabled=yes` -----------------

_VERBS = frozenset(
    {"add", "set", "remove", "disable", "enable", "unset", "edit", "move", "print", "comment"}
)


def parse_path_command(text: str) -> Iterator[RawStatement]:
    """A ``/menu path`` line sets the context for the commands that follow it.

    ``/ip service set telnet disabled=yes`` (path and command on one line) is split the same
    way, so both export styles give identical statements.
    """
    path: tuple[str, ...] = ()
    for start, end, line in logical_lines(text, continuation=True):
        if not line or line.startswith(COMMENTS):
            continue
        body = line
        if line.startswith("/"):
            words = line.split()
            cut = next(
                (i for i, w in enumerate(words) if i > 0 and (w in _VERBS or "=" in w)),
                len(words),
            )
            path = (" ".join(words[:cut]),)
            if cut == len(words):
                continue
            body = " ".join(words[cut:])
        yield RawStatement(path, body, start, end)


# --- flat fallback ------------------------------------------------------------------------------


def parse_flat(text: str) -> Iterator[RawStatement]:
    """Anything else: one statement per non-blank, non-comment line (PLAN §6.1)."""
    for lineno, line in enumerate(split_lines(text), start=1):
        body = line.strip()
        if body and not body.startswith(("#", "!")):
            yield RawStatement((), body, lineno, lineno)

"""Brace family: Juniper Junos, VyOS, PAN-OS CLI (PLAN §6.1, TODO M2.10).

``name { … }`` opens a block, ``;`` ends a statement, ``#`` and ``/* */`` are comments. Block
headers are statements too. ``system { services { telnet; } }`` gives three statements, the last
being ``telnet`` with path ``("system", "services")``.

Junos marks deactivated configuration with ``inactive:``. The device ignores it, so we do too:
an inactive statement or block produces no statements. ``protect:`` is only an edit lock and is
stripped.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from kasauti.shape.base import ParseError, RawStatement

_LEX = re.compile(
    r"""
    (?P<nl>\n)
  | (?P<ws>[ \t\r\f\v]+)
  | (?P<comment>\#[^\n]*)
  | (?P<block_comment>/\*.*?\*/)
  | (?P<string>"(?:[^"\\\n]|\\.)*")
  | (?P<open>\{)
  | (?P<close>\})
  | (?P<end>;)
  | (?P<word>[^\s{};"\#]+)
  | (?P<bad>.)
    """,
    re.VERBOSE | re.DOTALL,
)
_INACTIVE = "inactive:"
_PROTECT = "protect:"


def parse(text: str) -> Iterator[RawStatement]:  # noqa: PLR0912 - one branch per token kind
    stack: list[tuple[str, bool, int]] = []  # (header, active, line opened)
    words: list[str] = []
    start = 0
    line = 1
    for m in _LEX.finditer(text):
        kind = m.lastgroup
        if kind == "nl":
            line += 1
        elif kind == "block_comment":
            line += m.group().count("\n")
        elif kind in ("string", "word"):
            if not words:
                start = line
            words.append(m.group())
        elif kind == "open":
            if not words:
                raise ParseError("'{' without a block name", line)
            active, header = _activity(words, line)
            parent_active = not stack or stack[-1][1]
            if active and parent_active:
                yield RawStatement(_path(stack), header, start, line)
            stack.append((header, active and parent_active, line))
            words = []
        elif kind == "end":
            if words:
                active, body = _activity(words, line)
                if active and (not stack or stack[-1][1]):
                    yield RawStatement(_path(stack), body, start, line)
            words = []
        elif kind == "close":
            if words:
                raise ParseError(f"statement {' '.join(words)!r} is missing ';'", line)
            if not stack:
                raise ParseError("'}' without a matching '{'", line)
            stack.pop()
        elif kind == "bad":
            raise ParseError(f"unexpected {m.group()!r} (unterminated string?)", line)
    if words:
        raise ParseError(f"statement {' '.join(words)!r} is missing ';'", line)
    if stack:
        raise ParseError(f"block {stack[-1][0]!r} opened here is never closed", stack[-1][2])


def _activity(words: list[str], line: int) -> tuple[bool, str]:
    active = True
    while words and words[0] in (_INACTIVE, _PROTECT):
        if words[0] == _INACTIVE:
            active = False
        words = words[1:]
    if not words:
        raise ParseError("a statement has only a marker (inactive:/protect:)", line)
    return active, " ".join(words)


def _path(stack: list[tuple[str, bool, int]]) -> tuple[str, ...]:
    return tuple(header for header, _, _ in stack)

"""Indent family: Cisco IOS/IOS-XE/NX-OS, Arista EOS, Aruba-CX, Dell OS10, Huawei VRP, …

A line's parent is the nearest earlier line with less indentation. ``!`` and ``#`` lines are
separators/comments. Every line becomes a statement, block headers included, because headers
carry meaning too (``line vty 0 4`` opens an entity).

Cisco delimited banners (``banner login ^C … ^C``) are consumed as one multi-line statement,
so free text inside a banner is never mistaken for configuration.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from kasauti.shape.base import RawStatement
from kasauti.shape.tokens import split_lines

COMMENT_PREFIXES = ("!", "#")
_BANNER = re.compile(r"^banner\s+\S+\s+(\^C|\S)")


def parse(text: str) -> Iterator[RawStatement]:
    stack: list[tuple[int, str]] = []
    lines = split_lines(text)
    i = 0
    while i < len(lines):
        raw = lines[i].expandtabs(8)
        body = raw.strip()
        lineno = i + 1
        i += 1
        if not body or body.startswith(COMMENT_PREFIXES):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0 and body == "end":
            continue  # Cisco end-of-config marker
        while stack and stack[-1][0] >= indent:
            stack.pop()
        line_end = lineno
        banner = _BANNER.match(body)
        if banner:
            line_end, i = _banner_end(lines, i, lineno, body[banner.end() :], banner.group(1))
        yield RawStatement(tuple(t for _, t in stack), body, lineno, line_end)
        stack.append((indent, body))


def _banner_end(lines: list[str], i: int, lineno: int, after: str, delim: str) -> tuple[int, int]:
    """Return (last line of the banner, index to continue from)."""
    if delim in after:
        return lineno, i  # single-line banner
    j = i
    while j < len(lines):
        if delim in lines[j]:
            return j + 1, j + 1
        j += 1
    return lineno, i  # unterminated: treat as a single line rather than swallow the file

"""Indent family: Cisco IOS/IOS-XE/NX-OS, Arista EOS, Aruba-CX, Dell OS10, Huawei VRP, …

A line's parent is the nearest earlier line with less indentation. ``!`` and ``#`` lines are
separators/comments. Every line becomes a statement, block headers included, because headers
carry meaning too (``line vty 0 4`` opens an entity).

Banners are consumed as one multi-line statement, so free text inside a banner is never
mistaken for configuration: Cisco delimited banners (``banner login ^C … ^C``) and Arista EOS
banners (``banner login`` then text, ended by a line that is just ``EOF``).
"""

from __future__ import annotations

import bisect
import itertools
import re
from collections.abc import Iterator

from kasauti.shape.base import RawStatement, check_depth
from kasauti.shape.tokens import split_lines

COMMENT_PREFIXES = ("!", "#")
_BANNER = re.compile(r"^banner\s+\S+\s+(\^C|\S)")
_EOF_BANNER = re.compile(r"^banner\s+\S+$")


MAX_BANNER_LINES = 500
"""A banner's closing delimiter (or EOS's ``EOF``) is looked for this many lines ahead. Real
banners run to a few dozen lines; without a bound, every unclosed banner would search to the
end of the file, and a file of them would cost its length squared (M2.07 review)."""
_EOF_LINE = re.compile(r"^[^\S\n]*EOF[^\S\n]*$", re.MULTILINE)


class _Lines:
    """The lines joined once, so a banner's end is found by a search in C over a bounded span
    rather than a Python loop over lines."""

    def __init__(self, lines: list[str]) -> None:
        self.text = "\n".join(lines)
        self.starts = list(itertools.accumulate((len(ln) + 1 for ln in lines[:-1]), initial=0))
        self._eofs: list[int] | None = None

    def _span(self, first: int) -> tuple[int, int]:
        last = min(first + MAX_BANNER_LINES, len(self.starts))
        end = self.starts[last] if last < len(self.starts) else len(self.text)
        return self.starts[first], end

    def containing(self, first: int, needle: str) -> int | None:
        """The index of the first line from ``first`` holding ``needle``, within the bound."""
        if first >= len(self.starts):
            return None
        start, end = self._span(first)
        at = self.text.find(needle, start, end)
        return None if at < 0 else bisect.bisect_right(self.starts, at) - 1

    def eof(self, first: int) -> int | None:
        """The index of the first line from ``first`` that is just ``EOF``, within the bound.
        Every EOF line is found once, on the first call; each call after is a binary search,
        so a file of banners that never end costs one pass, not one pass per banner."""
        if self._eofs is None:
            self._eofs = [
                bisect.bisect_right(self.starts, m.start()) - 1
                for m in _EOF_LINE.finditer(self.text)
            ]
        at = bisect.bisect_left(self._eofs, first)
        if at < len(self._eofs) and self._eofs[at] < first + MAX_BANNER_LINES:
            return self._eofs[at]
        return None


def parse(text: str) -> Iterator[RawStatement]:
    stack: list[tuple[int, str]] = []
    lines = split_lines(text)
    joined: _Lines | None = None  # built on the first banner only
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
        eof_banner = banner is None and _EOF_BANNER.match(body)
        if banner is not None and banner.group(1) not in body[banner.end() :]:
            joined = joined or _Lines(lines)
            # Cisco: the banner runs to the next line holding its delimiter; unclosed, it is
            # one line rather than swallowing the file.
            found = joined.containing(i, banner.group(1))
            if found is not None:
                line_end = i = found + 1
        elif eof_banner:
            joined = joined or _Lines(lines)
            # EOS: the banner runs to a line that is just EOF; with none, nothing is swallowed.
            found = joined.eof(i)
            if found is not None:
                line_end = i = found + 1
        check_depth(len(stack) + 1, lineno)
        yield RawStatement(tuple(t for _, t in stack), body, lineno, line_end)
        stack.append((indent, body))

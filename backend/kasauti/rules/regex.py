"""Linear-time regular expressions for the ``matches`` operator (docs/spec/rule-language.md §2).

Configuration text is attacker-controlled, so a backtracking engine would let a crafted line
stall an audit (ReDoS). RE2 (BSD-3-Clause) guarantees time linear in the input.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

import re2


class PatternError(ValueError):
    pass


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> Any:
    try:
        return re2.compile(pattern)
    except re2.error as err:
        raise PatternError(f"{pattern!r} is not a valid RE2 pattern: {err}") from err


@lru_cache(maxsize=512)
def _per_line(pattern: str) -> Any:
    """``pattern`` for :func:`first_line`: ``^``/``$`` at line ends, and no match may contain a
    newline (RE2's ``never_nl``), so one search of the whole text finds exactly what searching
    each line on its own would."""
    options = re2.Options()
    options.never_nl = True
    try:
        return re2.compile(f"(?m){pattern}", options)
    except re2.error as err:
        raise PatternError(f"{pattern!r} is not a valid RE2 pattern: {err}") from err


def validate(pattern: str) -> None:
    _compiled(pattern)
    _per_line(pattern)


def first_line(pattern: str, text: str) -> tuple[int, dict[str, str]] | None:
    """The first line of ``text`` (lines joined by ``\\n``) that ``pattern`` matches, as if
    each line were searched on its own: its 1-based number and the named groups that took
    part. One linear pass over the text; searching line by line cost a call per line, which
    a file of a million short lines turns into minutes (M2.07 review)."""
    for line, _start, groups in matching_lines(pattern, text):
        return line, groups
    return None


def matching_lines(pattern: str, text: str) -> Iterator[tuple[int, int, dict[str, str]]]:
    """Every line of ``text`` that ``pattern`` matches, in order, as :func:`first_line` finds
    the first: its 1-based number, the offset it starts at, and the named groups. Each search
    resumes at the next line, and line numbers are counted as it goes."""
    compiled = _per_line(pattern)
    pos, line, counted = 0, 1, 0
    while (m := compiled.search(text, pos)) is not None:
        line += text.count("\n", counted, m.start())
        counted = m.start()
        start = text.rfind("\n", 0, m.start()) + 1
        yield line, start, {k: str(v) for k, v in m.groupdict().items() if v is not None}
        pos = text.find("\n", m.start())
        if pos < 0:
            return
        pos += 1


def search(pattern: str, text: str) -> bool:
    return _compiled(pattern).search(text) is not None


def group(pattern: str, text: str, name: str) -> str | None:
    """The named group of the first match, or None."""
    m = _compiled(pattern).search(text)
    if m is None:
        return None
    value = m.group(name)
    return str(value) if value is not None else None


def groups(pattern: str, text: str) -> dict[str, str] | None:
    """The named groups of the first match (those that took part), or None without a match."""
    m = _compiled(pattern).search(text)
    if m is None:
        return None
    return {k: str(v) for k, v in m.groupdict().items() if v is not None}


def group_names(pattern: str) -> tuple[str, ...]:
    """The pattern's named groups, in order."""
    return tuple(sorted(_compiled(pattern).groupindex, key=_compiled(pattern).groupindex.get))


def records(pattern: str, text: str) -> Iterator[tuple[int, dict[str, str]]]:
    """Every non-overlapping match in ``text``: its start offset and its named groups (a group
    that took no part in the match is left out). Linear time, like every search here."""
    for m in _compiled(pattern).finditer(text):
        yield m.start(), {k: str(v) for k, v in m.groupdict().items() if v is not None}

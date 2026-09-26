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


def validate(pattern: str) -> None:
    _compiled(pattern)


def search(pattern: str, text: str) -> bool:
    return _compiled(pattern).search(text) is not None


def group(pattern: str, text: str, name: str) -> str | None:
    """The named group of the first match, or None."""
    m = _compiled(pattern).search(text)
    if m is None:
        return None
    value = m.group(name)
    return str(value) if value is not None else None


def group_names(pattern: str) -> tuple[str, ...]:
    """The pattern's named groups, in order."""
    return tuple(sorted(_compiled(pattern).groupindex, key=_compiled(pattern).groupindex.get))


def records(pattern: str, text: str) -> Iterator[tuple[int, dict[str, str]]]:
    """Every non-overlapping match in ``text``: its start offset and its named groups (a group
    that took no part in the match is left out). Linear time, like every search here."""
    for m in _compiled(pattern).finditer(text):
        yield m.start(), {k: str(v) for k, v in m.groupdict().items() if v is not None}

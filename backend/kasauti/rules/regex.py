"""Linear-time regular expressions for the ``matches`` operator (docs/spec/rule-language.md §2).

Configuration text is attacker-controlled, so a backtracking engine would let a crafted line
stall an audit (ReDoS). RE2 (BSD-3-Clause) guarantees time linear in the input.
"""

from __future__ import annotations

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

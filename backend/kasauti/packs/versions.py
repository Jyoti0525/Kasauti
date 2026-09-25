"""Vendor-agnostic OS version ordering and ranges (PLAN §9.4).

Mappings, defaults and recipes carry an ``os_versions`` range, so a vendor's syntax or default
change in a new release is a new scoped entry, not a code change.

Versions are compared by a *natural key*: digit runs compare as numbers, letter runs as
case-folded text, and a version that extends another sorts after it. This orders every scheme
we've met without per-vendor code, for example::

    Cisco    17.3.4 < 17.3.4a < 17.12.1
    Junos    21.4R3 < 21.4R3-S2 < 22.1R1
    PAN-OS   10.2.9 < 10.2.9-h1 < 11.0.0
    FortiOS  6.4.9  < 7.0.0

A range is ``*`` (any version) or comma-separated clauses joined by AND:
``">=6.0"``, ``">=16.9,<17.3"``, ``"==21.4R3-S2"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Literal

_PART = re.compile(r"\d+|[A-Za-z]+")
_CLAUSE = re.compile(r"^\s*(>=|<=|==|!=|>|<)\s*([0-9A-Za-z][0-9A-Za-z.\-()]*)\s*$")

Op = Literal[">=", "<=", "==", "!=", ">", "<"]


@total_ordering
@dataclass(frozen=True, slots=True)
class Version:
    text: str
    key: tuple[tuple[int, int | str], ...]

    @classmethod
    def parse(cls, text: str) -> Version:
        parts = _PART.findall(text)
        if not parts:
            raise ValueError(f"not a version: {text!r}")
        key = tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts)
        return cls(text, key)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self.key < other.key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)


@dataclass(frozen=True, slots=True)
class VersionRange:
    text: str
    clauses: tuple[tuple[Op, Version], ...]

    @classmethod
    def parse(cls, text: str) -> VersionRange:
        stripped = text.strip()
        if stripped in ("*", ""):
            return cls("*", ())
        clauses: list[tuple[Op, Version]] = []
        for raw in stripped.split(","):
            m = _CLAUSE.match(raw)
            if m is None:
                raise ValueError(f"bad version clause {raw.strip()!r} in {text!r}")
            op: Op = m.group(1)  # type: ignore[assignment]
            clauses.append((op, Version.parse(m.group(2))))
        return cls(stripped, tuple(clauses))

    def contains(self, version: str | Version) -> bool:
        v = Version.parse(version) if isinstance(version, str) else version
        return all(_holds(v, op, bound) for op, bound in self.clauses)

    @property
    def is_any(self) -> bool:
        return not self.clauses


def _holds(v: Version, op: Op, bound: Version) -> bool:
    match op:
        case ">=":
            return v >= bound
        case "<=":
            return v <= bound
        case ">":
            return v > bound
        case "<":
            return v < bound
        case "==":
            return v == bound
        case "!=":
            return v != bound


def validate_range(text: str) -> str:
    """Pydantic ``AfterValidator`` helper: keep the text, reject malformed ranges early."""
    VersionRange.parse(text)
    return text

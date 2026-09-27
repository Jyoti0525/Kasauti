"""What every shape-family parser emits before tokenising (PLAN §6.2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RawStatement:
    path: tuple[str, ...]
    text: str
    line_start: int
    line_end: int


MAX_DEPTH = 100
"""Blocks nested deeper than this aren't parsed as blocks (TODO M2.07). Real configurations
nest about 10 to 20 levels (a PAN-OS security rule's members, a Junos firewall term); every
statement carries its ancestors' path, so depth costs depth squared, and a file nested a
million levels deep (a few MB of ``<a>``) would take the worker's whole time limit. A file
past this depth is parsed line by line instead, with a warning (``parse_text``'s fallback)."""


class ParseError(ValueError):
    """The text isn't valid for the family it was parsed as. ``line`` is 1-based, if known."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


def check_depth(depth: int, line: int | None = None) -> None:
    """Refuse to open a block ``depth`` levels deep once that passes :data:`MAX_DEPTH`."""
    if depth > MAX_DEPTH:
        raise ParseError(f"blocks nested more than {MAX_DEPTH} levels deep", line)

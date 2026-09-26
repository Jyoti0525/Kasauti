"""What every shape-family parser emits before tokenising (PLAN §6.2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RawStatement:
    path: tuple[str, ...]
    text: str
    line_start: int
    line_end: int


class ParseError(ValueError):
    """The text isn't valid for the family it was parsed as. ``line`` is 1-based, if known."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line

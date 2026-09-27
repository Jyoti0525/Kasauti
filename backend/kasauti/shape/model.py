"""Universal Config Tree: what every shape-family parser produces (PLAN §6)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ShapeFamily(StrEnum):
    """The seven structural families plus the flat fallback (PLAN §6.1)."""

    INDENT = "indent"
    BRACE = "brace"
    SET_PATH = "set_path"
    BLOCK_EDIT = "block_edit"
    PATH_COMMAND = "path_command"
    XML = "xml"
    JSON_YAML = "json_yaml"
    FLAT = "flat"


@dataclass(frozen=True, slots=True)
class Statement:
    """One leaf of a configuration, with the chain of blocks it lives in.

    Example: ``path = ("line vty 0 4",)``, ``text = "transport input ssh telnet"``.
    For XML/JSON families the parser renders a leaf as ``"<key> <value>"`` and its ancestors as
    ``path``, so one mapping language serves every family.

    A slotted dataclass, not a pydantic model: there is one per line, built only by the
    parsers, never read from outside or written out, and a model's per-instance dictionaries
    made the tree about 60 times the size of its configuration (M2.09).
    """

    path: tuple[str, ...]
    tokens: tuple[str, ...]
    text: str
    line_start: int
    line_end: int
    family: ShapeFamily
    pattern_key: str | None = None
    """Drain3 template with variables abstracted (``<INT> <IP> <IFNAME> <STR> <LIST>``, §6.2)."""

    def __post_init__(self) -> None:
        if not 1 <= self.line_start <= self.line_end:
            raise ValueError("lines must satisfy 1 <= line_start <= line_end")


_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ConfigTree:
    source_file: str
    sha256: str
    family: ShapeFamily
    statements: tuple[Statement, ...]
    warnings: tuple[str, ...] = ()
    """Why the tree isn't what was expected, e.g. a flat fallback after a syntax error."""

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("sha256 must be 64 lowercase hex digits")

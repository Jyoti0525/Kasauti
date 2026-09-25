"""Universal Config Tree: what every shape-family parser produces (PLAN §6)."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class Statement(BaseModel):
    """One leaf of a configuration, with the chain of blocks it lives in.

    Example: ``path = ("line vty 0 4",)``, ``text = "transport input ssh telnet"``.
    For XML/JSON families the parser renders a leaf as ``"<key> <value>"`` and its ancestors as
    ``path``, so one mapping language serves every family.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: tuple[str, ...] = ()
    tokens: tuple[str, ...]
    text: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    family: ShapeFamily
    pattern_key: str | None = None
    """Drain3 template with variables abstracted (``<INT> <IP> <IFNAME> <STR> <LIST>``, §6.2)."""

    @model_validator(mode="after")
    def _lines(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class ConfigTree(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_file: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    family: ShapeFamily
    statements: tuple[Statement, ...]

"""Apply a fix's commands to a copy of a configuration, one editor per shape family (PLAN §14.3).

The commands an administrator is shown are the ones applied here, so the re-audit proves the
exact text in the report. Each editor also says what the change altered (lines removed and
added, by block), which is where the rollback and the verify step's expectations come from.

Editors work on text and know a family's syntax, never a vendor's features: which negations a
running configuration keeps (``no ip http server``) and how to show a block come from the pack's
``verify.yaml``, so a new vendor in a known family needs data, not code (R-08).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from kasauti.packs.model import JsonEdit, Session


class EditError(ValueError):
    """The change can't be applied to this configuration as written. User-safe text."""


@dataclass(frozen=True)
class Change:
    lines: tuple[str, ...]
    """What is typed, in order, with site values already filled in (examples, to verify)."""
    stored: tuple[str, ...]
    """How each line reads in the saved configuration (usually the same line)."""
    replaces: tuple[str, ...] = ()
    edits: tuple[JsonEdit, ...] = ()


@dataclass
class Applied:
    text: str
    removed: list[tuple[str, str]] = field(default_factory=list)
    """``(block, line)`` pairs taken out; ``block`` is ``""`` at the top level."""
    added: list[tuple[str, str]] = field(default_factory=list)
    replaced: list[tuple[str, str, str]] = field(default_factory=list)
    """``(block, old, new)``: a setting overwritten, undone by writing the old line back."""
    created: list[str] = field(default_factory=list)
    """Blocks the change created, undone by removing each whole."""
    paths: list[str] = field(default_factory=list)
    """What to show before and after: the blocks or command paths the change touched."""


class Editor(Protocol):
    def apply(self, text: str, change: Change, session: Session) -> Applied: ...

    def rollback(self, applied: Applied, session: Session) -> tuple[str, ...]: ...


def editor_for(family: str) -> Editor | None:
    # The editors import this module's types, so they're imported when first asked for.
    from kasauti.remediation.editors import (  # noqa: PLC0415
        blockedit,
        indent,
        json_edit,
        setpath,
        xml_set,
    )

    editors: dict[str, Editor] = {
        "indent": indent.IndentEditor(),
        "brace": setpath.SetPathEditor(),
        "set_path": setpath.SetPathEditor(),
        "block_edit": blockedit.BlockEditEditor(),
        "xml": xml_set.XmlSetEditor(),
        "json_yaml": json_edit.JsonEditor(),
    }
    return editors.get(family)

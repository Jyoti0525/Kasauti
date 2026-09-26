"""Text -> Universal Config Tree (PLAN §6). The one entry point for every shape family."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable

from kasauti.ingest.mask import mask_secrets
from kasauti.shape import brace, indent, lines, structured
from kasauti.shape.base import ParseError, RawStatement
from kasauti.shape.detect import detect_family
from kasauti.shape.model import ConfigTree, ShapeFamily, Statement
from kasauti.shape.patterns import pattern_key
from kasauti.shape.tokens import tokenize

Parser = Callable[[str], Iterable[RawStatement]]

PARSERS: dict[ShapeFamily, Parser] = {
    ShapeFamily.INDENT: indent.parse,
    ShapeFamily.BRACE: brace.parse,
    ShapeFamily.SET_PATH: lines.parse_set_path,
    ShapeFamily.BLOCK_EDIT: lines.parse_block_edit,
    ShapeFamily.PATH_COMMAND: lines.parse_path_command,
    ShapeFamily.XML: structured.parse_xml,
    ShapeFamily.JSON_YAML: structured.parse_json_yaml,
    ShapeFamily.FLAT: lines.parse_flat,
}

# MikroTik: `comment="a b"` is one token; see _path_command_tokens.
_PC_TOKEN = re.compile(r'[^\s="]+="(?:[^"\\]|\\.)*"|"(?:[^"\\]|\\.)*"|\S+')


def parse_text(
    text: str,
    *,
    source_file: str,
    family: ShapeFamily | None = None,
    sha256: str | None = None,
    fallback: bool = True,
) -> ConfigTree:
    """Parse ``text`` as ``family`` (detected if not given).

    If the family's parser rejects the text and ``fallback`` is set, the flat fallback is used
    and the reason is kept in ``ConfigTree.warnings``: the audit continues, with every line
    still available to mappings and to the Training Studio, and the report says why.
    """
    chosen = family or detect_family(text)
    warnings: list[str] = []
    try:
        raws = list(PARSERS[chosen](text))
    except ParseError as err:
        if not fallback:
            raise
        warnings.append(f"not valid {chosen.value} syntax ({err}); parsed line by line instead")
        chosen = ShapeFamily.FLAT
        raws = list(lines.parse_flat(text))
    statements = tuple(_statement(r, chosen) for r in raws if r.text)
    return ConfigTree(
        source_file=source_file,
        sha256=sha256 or hashlib.sha256(text.encode("utf-8")).hexdigest(),
        family=chosen,
        statements=statements,
        warnings=tuple(warnings),
    )


def statement_tokens(text: str, family: ShapeFamily) -> tuple[str, ...]:
    if family is ShapeFamily.PATH_COMMAND:
        return _path_command_tokens(text)
    return tokenize(text)


def _statement(raw: RawStatement, family: ShapeFamily) -> Statement:
    tokens = statement_tokens(raw.text, family)
    # The key is shown in reports and the Studio, so it's built from the masked text: a secret
    # too short to look random (``password 7 abc123``) must not leak through its pattern.
    masked = statement_tokens(mask_secrets(raw.text), family)
    return Statement(
        path=raw.path,
        tokens=tokens,
        text=raw.text,
        line_start=raw.line_start,
        line_end=raw.line_end,
        family=family,
        pattern_key=pattern_key(masked),
    )


def _path_command_tokens(text: str) -> tuple[str, ...]:
    """``disabled=yes`` -> ``disabled=``, ``yes`` so a slot can capture the value."""
    out: list[str] = []
    for tok in _PC_TOKEN.findall(text):
        key, sep, value = tok.partition("=")
        if sep and key and not tok.startswith('"'):
            out.append(f"{key}=")
            out.append(value if value else '""')
        else:
            out.append(tok)
    return tuple(out)

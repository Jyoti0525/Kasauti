"""Minimal ingestion (PLAN §5.2, TODO M1.01): bytes in, a validated text :class:`Artifact` out.

Checks, in order: size limit, binary sniffing, encoding detection. Archives, companion files and
device grouping arrive in M2 (TODO M2.04-M2.07); sandboxed parse workers in M5.02.

Encoding detection uses charset-normalizer (MIT), not chardet (LGPL). UTF-8 and BOM-marked
UTF-16/32 are decoded directly; detection only runs for anything else.
"""

from __future__ import annotations

import codecs
import hashlib
from pathlib import Path

from charset_normalizer import from_bytes

from kasauti.ingest.model import Artifact

MAX_BYTES = 20 * 1024 * 1024
"""Largest configuration we accept. Real running-configs are far smaller; the limit bounds
parser memory and time for hostile input."""

_SNIFF_BYTES = 8192
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
# Control bytes that never appear in text files. Tab, LF, VT, FF, CR and ESC do appear.
_BINARY_BYTES = frozenset(range(32)) - {9, 10, 11, 12, 13, 27}
_BINARY_RATIO = 0.10


class IngestError(ValueError):
    """The file can't be audited as text. The message is safe to show to users."""


def decode(data: bytes, name: str, *, kind: str = "config") -> Artifact:
    if len(data) > MAX_BYTES:
        raise IngestError(f"{name}: {len(data)} bytes exceeds the {MAX_BYTES}-byte limit")
    if not data.strip():
        raise IngestError(f"{name}: file is empty")
    bom_encoding = next((enc for bom, enc in _BOMS if data.startswith(bom)), None)
    if bom_encoding is None and looks_binary(data):
        raise IngestError(f"{name}: looks like a binary file, not a text configuration")
    text, encoding = _decode_text(data, name, bom_encoding)
    return Artifact(
        name=name,
        text=text,
        sha256=hashlib.sha256(data).hexdigest(),
        encoding=encoding,
        kind=kind,
    )


def read_file(path: Path, *, kind: str = "config") -> Artifact:
    """Read and validate one file. The size is checked before the file is read."""
    try:
        size = path.stat().st_size
    except OSError as err:
        raise IngestError(f"{path.name}: cannot read ({err.strerror})") from err
    if size > MAX_BYTES:
        raise IngestError(f"{path.name}: {size} bytes exceeds the {MAX_BYTES}-byte limit")
    if not path.is_file():
        raise IngestError(f"{path.name}: not a regular file")
    return decode(path.read_bytes(), path.name, kind=kind)


def looks_like_text(head: bytes) -> bool:
    """For a file's first bytes (at least one): marked as Unicode, or not binary. Cheap enough to
    run on every upload before any worker decodes the file."""
    return any(head.startswith(bom) for bom, _ in _BOMS) or not looks_binary(head)


def looks_binary(data: bytes) -> bool:
    head = data[:_SNIFF_BYTES]
    if b"\x00" in head:
        return True
    odd = sum(1 for b in head if b in _BINARY_BYTES)
    return odd / len(head) > _BINARY_RATIO


def _decode_text(data: bytes, name: str, bom_encoding: str | None) -> tuple[str, str]:
    if bom_encoding is not None:
        try:
            return data.decode(bom_encoding), bom_encoding
        except UnicodeDecodeError as err:
            raise IngestError(f"{name}: invalid {bom_encoding} text") from err
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    best = from_bytes(data).best()
    if best is None:
        raise IngestError(f"{name}: cannot determine the text encoding")
    return str(best), best.encoding

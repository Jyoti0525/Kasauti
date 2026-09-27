"""Job results as stored: gzip-compressed canonical JSON (TODO M2.04 follow-up).

An audit's JSON is about 30 times the size of the configuration it describes (every fact
carries its evidence), and so repetitive that gzip brings it back below the configuration's
own size. So a worker streams its result straight into gzip, the pool checks the compressed
bytes without parsing them, the database keeps them compressed, and the API hands them to the
browser as they are (``Content-Encoding: gzip``). The full JSON text never has to exist in the
server's memory, and the limits below are on bytes a worker can really make the server hold.

The compressed text is still canonical JSON (sorted keys, no whitespace), so a decoded result
is exactly the object the handler returned.
"""

from __future__ import annotations

import json
import zlib
from collections.abc import Iterator
from typing import Any

RESULT_LIMIT = 64 * 1024 * 1024
"""Bytes of *compressed* result a job may return. Measured 2026-09-27: an audit's JSON is 31
times its configuration's size and compresses to 0.8 times it; the densest input found (a bare
``interface`` line after line) compresses to 2.2 times. So a configuration at the 20 MiB upload
limit gives at most about 44 MiB: no file the upload accepts can fail here."""
RESULT_EXPANDED_LIMIT = 2 * 1024 * 1024 * 1024
"""Bytes a stored result may expand to. The densest input measured expands 92 times its size
(1.8 GiB for 20 MiB); this bounds what a reader of a result must be ready for, and how long
checking one can take."""
GZIP_MAGIC = b"\x1f\x8b"
"""How a stored result starts; a JSON text never does."""
_GZIP = 31
"""zlib's ``wbits`` for the gzip container."""
_LEVEL = 6
_CHUNK = 1024 * 1024

_ENCODER = json.JSONEncoder(
    sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
)


class ResultError(ValueError):
    """Stored bytes that aren't a result: damaged, not one gzip member, not a JSON object, or
    larger than :data:`RESULT_EXPANDED_LIMIT` once expanded."""


class ResultTooLargeError(ResultError):
    """A result that expands past the limit."""


def encode_result(obj: dict[str, Any]) -> bytes:
    """``obj`` as gzip-compressed canonical JSON, written in chunks so the whole text is never
    held at once. :class:`TypeError` or :class:`ValueError` if it isn't JSON."""
    packer = zlib.compressobj(_LEVEL, zlib.DEFLATED, _GZIP)
    out: list[bytes] = []
    pending: list[str] = []
    size = 0
    for piece in _ENCODER.iterencode(obj):
        pending.append(piece)
        size += len(piece)
        if size >= _CHUNK:
            out.append(packer.compress("".join(pending).encode()))
            pending, size = [], 0
    out.append(packer.compress("".join(pending).encode()))
    out.append(packer.flush())
    return b"".join(out)


def expand(blob: bytes, *, limit: int = RESULT_EXPANDED_LIMIT) -> Iterator[bytes]:
    """The JSON text in chunks of at most 1 MiB, checking as it goes: :class:`ResultError` if
    the bytes are damaged, hold more than one gzip member, or expand past ``limit``."""
    if not blob.startswith(GZIP_MAGIC):
        raise ResultError("not gzip")
    unpacker = zlib.decompressobj(_GZIP)
    total = 0
    data = blob
    while not unpacker.eof:
        try:
            # At most 1 MiB out per call; what it didn't get to is kept in unconsumed_tail.
            chunk = unpacker.decompress(data, _CHUNK)
        except zlib.error as err:
            raise ResultError("damaged") from err
        data = unpacker.unconsumed_tail
        if not chunk and not data:
            break  # no input left and nothing more to give: the stream was cut short
        total += len(chunk)
        if total > limit:
            raise ResultTooLargeError(f"expands past {limit} bytes")
        if chunk:
            yield chunk
    if not unpacker.eof:
        raise ResultError("cut short")
    if unpacker.unused_data:
        raise ResultError("more than one gzip member")


def check_result(blob: bytes, *, limit: int = RESULT_EXPANDED_LIMIT) -> None:
    """Everything :func:`expand` checks, plus that the text is a JSON object (it starts with
    ``{`` and ends with ``}``; the worker wrote it with :func:`encode_result`, so a full parse
    here would only cost the server memory)."""
    first = last = b""
    for chunk in expand(blob, limit=limit):
        first = first or chunk[:1]
        last = chunk[-1:]
    if (first, last) != (b"{", b"}"):
        raise ResultError("not a JSON object")


def decode_result(blob: bytes, *, limit: int = RESULT_EXPANDED_LIMIT) -> dict[str, Any]:
    """The result as an object. Holds the whole text in memory: for tests, the command line
    and small results; the API streams instead."""
    obj = json.loads(b"".join(expand(blob, limit=limit)))
    if not isinstance(obj, dict):
        raise ResultError("not a JSON object")
    return obj


__all__ = [
    "GZIP_MAGIC",
    "ResultError",
    "ResultTooLargeError",
    "check_result",
    "decode_result",
    "encode_result",
    "expand",
]

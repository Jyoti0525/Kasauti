"""Stored job results: gzip-compressed canonical JSON (TODO M2.04 follow-up)."""

from __future__ import annotations

import gzip
import json
import zlib

import pytest

from kasauti.jobs.child import canonical
from kasauti.jobs.results import (
    GZIP_MAGIC,
    ResultError,
    ResultTooLargeError,
    check_result,
    decode_result,
    encode_result,
    expand,
)

BIG = {"rows": [{"n": i, "text": f"interface Gi1/0/{i}", "ok": i % 2 == 0} for i in range(40_000)]}
"""About 1.6 MiB of JSON: written in more than one chunk."""


@pytest.mark.parametrize("obj", [{}, {"b": 1, "a": [1.5, None, "é2028"]}, BIG])
def test_the_text_is_the_canonical_json_in_standard_gzip(obj: dict[str, object]) -> None:
    blob = encode_result(obj)
    assert blob.startswith(GZIP_MAGIC)
    assert gzip.decompress(blob).decode() == canonical(obj)  # any gzip reader can open it
    assert decode_result(blob) == obj
    check_result(blob)


def test_expanding_comes_in_bounded_chunks() -> None:
    blob = encode_result(BIG)
    chunks = list(expand(blob))
    assert len(chunks) > 1
    assert max(map(len, chunks)) <= 1024 * 1024
    assert b"".join(chunks) == canonical(BIG).encode()


def test_repetitive_results_compress_far_below_their_size() -> None:
    size = len(canonical(BIG).encode())
    assert len(encode_result(BIG)) < size / 10


@pytest.mark.parametrize("bad", [{"x": float("nan")}, {"x": {1, 2}}, {"x": "\ud800"}])
def test_what_isnt_json_is_refused_when_encoding(bad: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        encode_result(bad)


def _gzip(data: bytes) -> bytes:
    packer = zlib.compressobj(9, zlib.DEFLATED, 31)
    return packer.compress(data) + packer.flush()


@pytest.mark.parametrize(
    ("blob", "why"),
    [
        (b'{"a":1}', "not gzip"),
        (_gzip(b'{"a":1}')[:-4], "cut short"),
        (_gzip(b'{"a":1}') + _gzip(b"{}"), "more than one gzip member"),
        (_gzip(b'{"a":1}') + b"\x00", "more than one gzip member"),
        (GZIP_MAGIC + b"\x08\x00" + bytes(40), "damaged"),
        (_gzip(b"[1]"), "not a JSON object"),
        (_gzip(b""), "not a JSON object"),
    ],
)
def test_bytes_that_arent_a_result_are_refused(blob: bytes, why: str) -> None:
    with pytest.raises(ResultError, match=why):
        check_result(blob)


def test_a_bomb_is_stopped_at_the_limit_not_expanded_whole() -> None:
    bomb = _gzip(b'{"x":"' + b"a" * (64 * 1024 * 1024) + b'"}')  # 64 MiB in about 64 KiB
    assert len(bomb) < 128 * 1024
    sizes: list[int] = []
    with pytest.raises(ResultTooLargeError, match="expands past 4194304 bytes"):
        sizes.extend(len(chunk) for chunk in expand(bomb, limit=4 * 1024 * 1024))
    assert sum(sizes) <= 4 * 1024 * 1024


def test_decoding_refuses_what_checking_refuses() -> None:
    with pytest.raises(ResultError):
        decode_result(_gzip(b"[1,2]"))
    with pytest.raises(json.JSONDecodeError):
        decode_result(_gzip(b"{nope}"))

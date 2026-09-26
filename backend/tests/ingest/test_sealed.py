"""Staged files sealed at rest (TODO M5.01, first part): AES-256-GCM in 64 KiB segments."""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from kasauti.ingest.sealed import HEADER, SEGMENT, TAG, Sealer, SealError, new_key

KEY = new_key()
LABEL = b"upload/file"


def _seal(data: bytes, *, key: bytes = KEY, label: bytes = LABEL, pieces: int = 7) -> bytes:
    """Written in uneven pieces, as a streamed upload is."""
    out = io.BytesIO()
    out.close = lambda: None  # type: ignore[method-assign]  # keep it readable after the writer closes
    with Sealer(key).writer(out, label) as sink:
        step = max(1, len(data) // pieces)
        for at in range(0, len(data), step):
            sink.write(data[at : at + step])
    return out.getvalue()


SIZES = [0, 1, SEGMENT - 1, SEGMENT, SEGMENT + 1, 3 * SEGMENT, 3 * SEGMENT + 17]


@pytest.mark.parametrize("size", SIZES)
def test_every_size_round_trips_and_the_disk_holds_only_ciphertext(size: int) -> None:
    data = os.urandom(size // 2) + b"enable secret 5 $1$PLACEHOLDER$x\n" * (size // 64)
    data = data[:size].ljust(size, b"x")
    sealed = _seal(data)
    segments = max(1, -(-size // SEGMENT))
    assert len(sealed) == HEADER + size + segments * TAG
    assert Sealer(KEY).open(sealed, LABEL) == data
    if size >= 32:
        assert b"PLACEHOLDER" not in sealed


def test_two_files_of_the_same_content_look_nothing_alike() -> None:
    data = b"hostname EDGE-R1\n" * 1000
    one, two = _seal(data), _seal(data)
    assert one[HEADER:] != two[HEADER:]  # a random prefix per file: nonces never repeat


def test_reading_seeks_across_segments() -> None:
    data = bytes(range(256)) * (3 * SEGMENT // 256) + b"tail"
    with Sealer(KEY).reader(io.BytesIO(_seal(data)), LABEL) as reader:
        for at in (0, SEGMENT - 3, SEGMENT, 2 * SEGMENT + 5, len(data) - 4):
            reader.seek(at)
            assert reader.read(9) == data[at : at + 9]
        assert reader.seek(0, io.SEEK_END) == len(data)
        assert reader.read() == b""


def test_a_zip_opens_through_it() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(5):
            zf.writestr(f"r{i}.cfg", os.urandom(40_000).hex())
    with (
        Sealer(KEY).reader(io.BytesIO(_seal(buf.getvalue())), LABEL) as reader,
        zipfile.ZipFile(reader) as zf,
    ):
        assert zf.testzip() is None
        assert len(zf.read("r4.cfg")) == 80_000


def _refused(sealed: bytes, *, key: bytes = KEY, label: bytes = LABEL) -> None:
    with pytest.raises(SealError):
        Sealer(key).open(sealed, label)


def test_the_wrong_key_or_name_opens_nothing() -> None:
    sealed = _seal(b"hostname EDGE-R1\n")
    _refused(sealed, key=new_key())  # the server restarted
    _refused(sealed, label=b"upload/another-file")  # a file passed off as another


@pytest.mark.parametrize("at", [HEADER - 1, HEADER, HEADER + SEGMENT + TAG - 1, -1])
def test_any_changed_byte_is_caught(at: int) -> None:
    sealed = bytearray(_seal(os.urandom(2 * SEGMENT + 100)))
    sealed[at] ^= 0x01
    _refused(bytes(sealed))


def test_cutting_it_short_is_caught_even_on_a_segment_boundary() -> None:
    sealed = _seal(os.urandom(3 * SEGMENT))
    _refused(sealed[: HEADER + 2 * (SEGMENT + TAG)])  # the last two segments dropped whole
    _refused(sealed[:-1])
    _refused(sealed[:HEADER])


def test_segments_can_t_be_reordered() -> None:
    sealed = _seal(os.urandom(3 * SEGMENT))
    stride = SEGMENT + TAG
    first, second = sealed[HEADER : HEADER + stride], sealed[HEADER + stride : HEADER + 2 * stride]
    _refused(sealed[:HEADER] + second + first + sealed[HEADER + 2 * stride :])


def test_what_isn_t_sealed_is_refused() -> None:
    _refused(b"hostname EDGE-R1\n")
    _refused(b"")
    with pytest.raises(ValueError, match="32 bytes"):
        Sealer(b"short")

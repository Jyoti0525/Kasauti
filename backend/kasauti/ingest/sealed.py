"""Staged files encrypted at rest (PLAN §5.2; the first part of TODO M5.01, v5.1.19).

An uploaded configuration waits on disk until its audit's worker reads it. Written in the
clear, a deleted file can still be recovered from the disk; written sealed, what stays behind
is ciphertext whose key never left the server's memory.

Format: an 8-byte magic, a random 7-byte file prefix, then the plaintext in 64 KiB segments,
each sealed with AES-256-GCM (16-byte tag). A segment's nonce is the prefix, its 4-byte
counter and a byte that is 1 on the last segment only, so segments can't be reordered, dropped
or cut off without a tag failing (the STREAM construction: Hoang, Reyhanitabar, Rogaway and
Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015).
Every tag also covers the file's label (its upload and file ids), so one sealed file can't be
passed off as another. Segments make the file seekable, which ``zipfile`` needs: reading a zip
entry decrypts only the segments it touches.

The key is 32 random bytes made when the server starts, held in memory only, and handed to
worker processes over the pipe that starts them, never through the database. A restart
therefore makes files staged before it unreadable; their jobs fail saying so.
"""

from __future__ import annotations

import io
import os
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"KSEAL\x00\x01\x00"
PREFIX = 7
HEADER = len(MAGIC) + PREFIX
SEGMENT = 64 * 1024
TAG = 16
KEY_BYTES = 32


class SealError(ValueError):
    """A sealed file that doesn't open: another key, another label, damaged or cut short."""


def new_key() -> bytes:
    return os.urandom(KEY_BYTES)


class Sealer:
    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError("an AES-256 key is 32 bytes")
        self._aead = AESGCM(key)

    def writer(self, raw: BinaryIO, label: bytes) -> SealedWriter:
        return SealedWriter(self._aead, raw, label)

    def reader(self, raw: BinaryIO, label: bytes) -> io.BufferedReader:
        return io.BufferedReader(SealedReader(self._aead, raw, label), buffer_size=SEGMENT)

    def open(self, data: bytes, label: bytes) -> bytes:
        """All of a sealed file's plaintext, from its bytes in memory."""
        with self.reader(io.BytesIO(data), label) as reader:
            return reader.read()


def _nonce(prefix: bytes, index: int, last: bool) -> bytes:
    return prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


class SealedWriter(io.RawIOBase):
    """Seals what is written, a segment at a time; :meth:`close` seals the last one. A
    segment is sealed only once more data follows it, so the last is always known."""

    def __init__(self, aead: AESGCM, raw: BinaryIO, label: bytes) -> None:
        super().__init__()
        self._aead = aead
        self._raw = raw
        self._aad = MAGIC + label
        self._prefix = os.urandom(PREFIX)
        self._index = 0
        self._pending = bytearray()
        raw.write(MAGIC + self._prefix)

    def writable(self) -> bool:
        return True

    def write(self, data: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        if self.closed:
            raise ValueError("write to a closed file")
        self._pending += data
        while len(self._pending) > SEGMENT:
            self._seal(bytes(self._pending[:SEGMENT]), last=False)
            del self._pending[:SEGMENT]
        return len(data)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._seal(bytes(self._pending), last=True)
            self._pending.clear()
            self._raw.flush()
        finally:
            self._raw.close()
            super().close()

    def _seal(self, plain: bytes, *, last: bool) -> None:
        nonce = _nonce(self._prefix, self._index, last)
        self._raw.write(self._aead.encrypt(nonce, plain, self._aad))
        self._index += 1


class SealedReader(io.RawIOBase):
    """The plaintext of a sealed file, seekable; each segment is checked as it is read."""

    def __init__(self, aead: AESGCM, raw: BinaryIO, label: bytes) -> None:
        super().__init__()
        self._aead = aead
        self._raw = raw
        self._aad = MAGIC + label
        head = raw.read(HEADER)
        if len(head) != HEADER or not head.startswith(MAGIC):
            raise SealError("not a sealed file")
        self._prefix = head[len(MAGIC) :]
        body = raw.seek(0, io.SEEK_END) - HEADER
        stride = SEGMENT + TAG
        self._segments = max(1, -(-body // stride))
        last = body - (self._segments - 1) * stride - TAG
        if not 0 <= last <= SEGMENT:
            raise SealError("cut short")
        self._size = (self._segments - 1) * SEGMENT + last
        self._pos = 0
        self._cached: tuple[int, bytes] | None = None

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._size}[whence]
        if base + offset < 0:
            raise ValueError("negative seek position")
        self._pos = base + offset
        return self._pos

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        if self._pos >= self._size:
            return 0
        index, skip = divmod(self._pos, SEGMENT)
        plain = self._segment(index)
        chunk = plain[skip : skip + len(buffer)]
        buffer[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)

    def close(self) -> None:
        if not self.closed:
            self._raw.close()
        super().close()

    def _segment(self, index: int) -> bytes:
        if self._cached is not None and self._cached[0] == index:
            return self._cached[1]
        last = index == self._segments - 1
        self._raw.seek(HEADER + index * (SEGMENT + TAG))
        sealed = self._raw.read(SEGMENT + TAG)
        try:
            plain = self._aead.decrypt(_nonce(self._prefix, index, last), sealed, self._aad)
        except InvalidTag:
            raise SealError("damaged, cut short, or sealed under another key or name") from None
        self._cached = (index, plain)
        return plain


__all__ = ["KEY_BYTES", "SealError", "SealedReader", "SealedWriter", "Sealer", "new_key"]

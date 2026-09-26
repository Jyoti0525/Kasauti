"""Where uploaded files wait for their audit job (PLAN §5.2; TODO M2.04, M5.01).

Until the evidence vault exists (TODO M5.01), an uploaded configuration is kept on disk only as
long as it has to be, and never in the clear:

* sealed as it arrives (AES-256-GCM, :mod:`kasauti.ingest.sealed`) under a key that lives only
  in the server's memory, so what a deleted file leaves on the disk is ciphertext;
* in ``<data dir>/staging/<upload id>/<file id>``, the directory owner-only (0700) and each file
  created owner-only (0600) on POSIX; on Windows the data directory's ACL applies;
* named by random ids, never by anything the user sent, so no file name can reach outside the
  staging directory;
* read once by the audit job's worker process, which deletes it at once, before parsing it;
* deleted by :func:`kasauti.ingest.store.housekeep` when its upload is discarded, expires
  unstarted, or its job ends without reading it (cancelled, say).

The database keeps names, sizes and hashes only; audit results carry masked text only.

A file being received is written as ``<file id>.part`` and keeps that name until its row is
committed, so housekeeping never mistakes a file in flight for one nobody refers to.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

from kasauti.ingest.sealed import SEGMENT, TAG, Sealer, SealError

PART = ".part"
_BINARY = getattr(os, "O_BINARY", 0)  # Windows: no newline translation
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def is_id(text: str) -> bool:
    """A UUID in its canonical form, as every staged name is."""
    try:
        return str(uuid.UUID(text)) == text
    except ValueError:
        return False


def _checked(*ids: str) -> None:
    for text in ids:
        if not is_id(text):
            raise ValueError("staging names are canonical UUIDs")


def key_id(key: bytes) -> str:
    """A name for a staging key that says nothing about it: which server sealed a file."""
    return hashlib.sha256(b"kasauti staging key\0" + key).hexdigest()[:16]


def _label(upload_id: str, file_id: str) -> bytes:
    return f"{upload_id}/{file_id}".encode()


class Staging:
    def __init__(self, root: Path, key: bytes) -> None:
        self.root = root
        self._sealer = Sealer(key)
        self.key_id = key_id(key)

    def prepare(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def path(self, upload_id: str, file_id: str) -> Path:
        _checked(upload_id, file_id)
        return self.root / upload_id / file_id

    def part(self, upload_id: str, file_id: str) -> Path:
        _checked(upload_id, file_id)
        return self.root / upload_id / f"{file_id}{PART}"

    def create(self, upload_id: str, file_id: str) -> io.RawIOBase:
        """A new ``.part`` file, owner-only, sealed as it is written. Refuses to replace
        anything already there."""
        path = self.part(upload_id, file_id)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY | _NOFOLLOW
        raw = os.fdopen(os.open(path, flags, 0o600), "wb")
        return self._sealer.writer(raw, _label(upload_id, file_id))

    def open(self, upload_id: str, file_id: str, *, part: bool = False) -> io.BufferedReader:
        """A staged file's plaintext, seekable (``zipfile`` needs that). :class:`SealError`
        if it doesn't open under this server's key."""
        path = self.part(upload_id, file_id) if part else self.path(upload_id, file_id)
        raw = path.open("rb")
        try:
            return self._sealer.reader(raw, _label(upload_id, file_id))
        except BaseException:
            raw.close()
            raise

    def commit(self, upload_id: str, file_id: str) -> None:
        """The file's row is committed: drop the ``.part`` suffix."""
        self.part(upload_id, file_id).replace(self.path(upload_id, file_id))

    def remove(self, upload_id: str, file_id: str) -> None:
        for path in (self.path(upload_id, file_id), self.part(upload_id, file_id)):
            path.unlink(missing_ok=True)

    def remove_upload(self, upload_id: str) -> None:
        _checked(upload_id)
        shutil.rmtree(self.root / upload_id, ignore_errors=True)

    def uploads(self) -> Iterator[str]:
        """Ids of the upload directories present. Anything else in the root is left alone:
        housekeeping deletes only what staging itself creates."""
        if not self.root.is_dir():
            return
        for entry in self.root.iterdir():
            if entry.is_dir() and not entry.is_symlink() and is_id(entry.name):
                yield entry.name

    def files(self, upload_id: str) -> Iterator[tuple[str, bool, float]]:
        """``(file id, is .part, modified time)`` for each staged file of an upload."""
        _checked(upload_id)
        folder = self.root / upload_id
        if not folder.is_dir():
            return
        for entry in folder.iterdir():
            name, part = entry.name, entry.name.endswith(PART)
            file_id = name.removesuffix(PART) if part else name
            if is_id(file_id) and entry.is_file() and not entry.is_symlink():
                try:
                    yield file_id, part, entry.stat().st_mtime
                except FileNotFoundError:  # its job read and deleted it just now
                    continue


def read_once(root: Path, key: bytes, upload_id: str, file_id: str, limit: int) -> bytes:
    """The staged file's plaintext, deleting the file as soon as it is read and before anything
    parses it: a parser crash or hang can't leave it behind. Decrypted in memory only.
    :class:`FileNotFoundError` if it is gone (already read, or deleted by housekeeping);
    :class:`SealError` if it doesn't open under ``key``; :class:`ValueError` if it is over
    ``limit`` bytes, which staging never lets in."""
    path = Staging(root, key).path(upload_id, file_id)
    most = limit + (limit // SEGMENT + 2) * TAG + 64  # the plaintext limit, sealed
    with path.open("rb") as handle:
        sealed = handle.read(most + 1)
    path.unlink(missing_ok=True)
    if len(sealed) > most:
        raise ValueError("staged file over the limit")
    data = Sealer(key).open(sealed, _label(upload_id, file_id))
    if len(data) > limit:
        raise ValueError("staged file over the limit")
    return data


def delete_staged(root: Path, upload_id: str, file_id: str) -> None:
    """Delete a staged file without reading it: one no key here can open."""
    _checked(upload_id, file_id)
    (root / upload_id / file_id).unlink(missing_ok=True)


__all__ = ["PART", "SealError", "Staging", "delete_staged", "is_id", "key_id", "read_once"]

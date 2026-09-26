"""Where uploaded files wait for their audit job (PLAN §5.2; TODO M2.04).

Until the encrypted evidence vault exists (TODO M5.01), an uploaded configuration is kept on
disk only as long as it has to be:

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

import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

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


class Staging:
    def __init__(self, root: Path) -> None:
        self.root = root

    def prepare(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def path(self, upload_id: str, file_id: str) -> Path:
        _checked(upload_id, file_id)
        return self.root / upload_id / file_id

    def part(self, upload_id: str, file_id: str) -> Path:
        _checked(upload_id, file_id)
        return self.root / upload_id / f"{file_id}{PART}"

    def create(self, upload_id: str, file_id: str) -> BinaryIO:
        """A new ``.part`` file, owner-only. Refuses to replace anything already there."""
        path = self.part(upload_id, file_id)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY | _NOFOLLOW
        return os.fdopen(os.open(path, flags, 0o600), "wb")

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


def read_once(root: Path, upload_id: str, file_id: str, limit: int) -> bytes:
    """The staged file's bytes, deleting the file as soon as they are read and before anything
    parses them: a parser crash or hang can't leave it behind. :class:`FileNotFoundError` if
    it is gone (already read, or deleted by housekeeping); :class:`ValueError` if it is over
    ``limit`` bytes, which staging never lets in."""
    path = Staging(root).path(upload_id, file_id)
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    path.unlink(missing_ok=True)
    if len(data) > limit:
        raise ValueError("staged file over the limit")
    return data

"""Taking files in (PLAN §5.1, §5.2; TODO M2.04): names, types, archives and their limits.

What arrives is a stream of bytes and a name the client chose. Neither is trusted:

* **Names are labels, never paths.** :func:`display_name` keeps a folder or archive path for the
  user to read and removes what could mislead or break a screen (``..``, drive letters, control
  and bidirectional-override characters). Files are stored under random ids
  (:mod:`kasauti.ingest.staging`), so no name, not even a ``.zip`` entry's, can place a file
  anywhere: zip-slip has nothing to act on.
* **Types by extension**, the list PLAN §5.1 gives, then a look at the first bytes: an empty or
  binary file is refused here, before any worker is spent on it. Decoding and parsing happen in
  the audit job's worker process (:mod:`kasauti.ingest.worker`).
* **Limits on what is actually read, not on what headers claim.** A file is at most
  :data:`~kasauti.ingest.read.MAX_BYTES`; a ``.zip`` body at most :data:`MAX_ARCHIVE_BYTES`,
  with at most :data:`MAX_ARCHIVE_ENTRIES` entries, expanding to at most
  :data:`MAX_EXPANDED_BYTES` in all. Each entry is decompressed as a stream and cut off at the
  limit, so a zip bomb costs the server at most that much work. Archives inside archives, and
  archive types other than zip, aren't opened. Python refuses overlapping entries (the
  "non-recursive" zip bomb) since 3.12.2.

Every refusal is a sentence fit to show the user, and names the file, never its content. The
full input-limit review (M2.07) builds on this.
"""

from __future__ import annotations

import hashlib
import stat
import unicodedata
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO

from kasauti.ingest.read import MAX_BYTES, looks_like_text
from kasauti.ingest.staging import Staging
from kasauti.ingest.table import NAME_LIMIT

ACCEPTED_SUFFIXES = (".txt", ".cfg", ".conf", ".log", ".xml", ".json", ".yaml", ".yml")
"""PLAN §5.1's types, plus ``.yml``, the other spelling of ``.yaml``."""
ARCHIVE_SUFFIX = ".zip"
OTHER_ARCHIVES = frozenset(
    {".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".lz", ".lzma", ".cab"}
)
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
"""Largest ``.zip`` body accepted."""
MAX_ARCHIVE_ENTRIES = 1000
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
"""Bytes one archive may expand to, over all its entries."""
SNIFF_BYTES = 8192
CHUNK = 1024 * 1024
_READABLE_METHODS = frozenset(
    {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
)
_LISTED = " ".join((*ACCEPTED_SUFFIXES, ARCHIVE_SUFFIX))


@dataclass(frozen=True, slots=True)
class Received:
    """One file, as taken in: accepted (``reason`` is None) or refused, and why."""

    id: str
    name: str
    size: int
    sha256: str | None
    reason: str | None = None

    @property
    def accepted(self) -> bool:
        return self.reason is None


def new_id() -> str:
    return str(uuid.uuid4())


def display_name(raw: str) -> str:
    """A name to show for ``raw``: its path parts, normalised, with nothing that could climb out
    of a folder, name a drive, or hide what the name says (control and format characters,
    including the right-to-left override that makes ``cfg.exe`` read as ``exe.cfg``)."""
    text = unicodedata.normalize("NFC", raw)
    kept = []
    for ch in text:
        category = unicodedata.category(ch)
        if category[0] == "C":
            continue
        kept.append(" " if category[0] == "Z" else ch)
    parts = [p.strip() for p in "".join(kept).replace("\\", "/").split("/")]
    parts = [p for p in parts if p not in ("", ".", "..")]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    name = "/".join(parts)
    if len(name) > NAME_LIMIT:
        name = "…" + name[-(NAME_LIMIT - 1) :]
    return name


def is_archive(name: str) -> bool:
    return PurePosixPath(name).suffix.lower() == ARCHIVE_SUFFIX


def body_limit(name: str) -> int:
    return MAX_ARCHIVE_BYTES if is_archive(name) else MAX_BYTES


def type_refusal(name: str) -> str | None:
    """Why a file of this name isn't taken, or None."""
    if not name:
        return "the file has no name"
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in ACCEPTED_SUFFIXES or suffix == ARCHIVE_SUFFIX:
        return None
    if suffix in OTHER_ARCHIVES:
        return f"{suffix} archives aren't opened; put the files in a .zip"
    return f"not a configuration file type (accepted: {_LISTED})"


def inspect(staging: Staging, upload_id: str, body: Received) -> list[Received]:
    """Check a request body received into its ``.part`` file: an archive is expanded into its
    entries (and the archive itself deleted); anything else is accepted or refused on its first
    bytes. Refused files are deleted; accepted ones stay as ``.part`` until their rows are
    committed."""
    if is_archive(body.name):
        try:
            with staging.open(upload_id, body.id, part=True) as archive:
                return _expand(staging, upload_id, archive, body)
        finally:
            staging.remove(upload_id, body.id)
    reason = _content_refusal(staging, upload_id, body.id, body.size)
    if reason is None:
        return [body]
    staging.remove(upload_id, body.id)
    return [Received(body.id, body.name, body.size, body.sha256, reason)]


def _content_refusal(staging: Staging, upload_id: str, file_id: str, size: int) -> str | None:
    if size == 0:
        return "the file is empty"
    with staging.open(upload_id, file_id, part=True) as handle:
        head = handle.read(SNIFF_BYTES)
    if not looks_like_text(head):
        return "looks like a binary file, not a text configuration"
    return None


def _expand(staging: Staging, upload_id: str, archive: BinaryIO, body: Received) -> list[Received]:
    name = body.name

    def refused(reason: str) -> list[Received]:
        return [Received(new_id(), name, body.size, None, reason)]

    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, EOFError, ValueError, NotImplementedError):
        return refused("not a readable zip archive")
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            return refused(
                f"the archive holds {len(infos)} entries; at most {MAX_ARCHIVE_ENTRIES} are opened"
            )
        received: list[Received] = []
        expanded = 0
        for info in infos:
            if info.is_dir():
                continue
            member = display_name(f"{name}/{display_name(info.filename)}")
            reason = _entry_refusal(info, member)
            if reason is None and expanded >= MAX_EXPANDED_BYTES:
                reason = _expanded_past()
            if reason is not None:
                received.append(Received(new_id(), member, 0, None, reason))
                continue
            item = _extract(
                zf,
                info,
                staging=staging,
                upload_id=upload_id,
                name=member,
                room=MAX_EXPANDED_BYTES - expanded,
            )
            expanded += item.size
            received.append(item)
    return received or refused("the archive holds no files")


def _entry_refusal(info: zipfile.ZipInfo, name: str) -> str | None:
    if stat.S_ISLNK(info.external_attr >> 16):
        return "a symbolic link, not a file"
    if info.flag_bits & 0x1:
        return "encrypted; put it in the archive unencrypted"
    suffix = PurePosixPath(name).suffix.lower()
    if suffix == ARCHIVE_SUFFIX or suffix in OTHER_ARCHIVES:
        return "an archive inside an archive isn't opened; upload it on its own"
    reason = type_refusal(name)
    if reason is not None:
        return reason
    if info.compress_type not in _READABLE_METHODS:
        return "compressed with a method Kasauti doesn't read; use standard zip (deflate)"
    if info.file_size > MAX_BYTES:
        return f"{info.file_size} bytes when expanded; the limit is {MAX_BYTES}"
    return None


def _expanded_past() -> str:
    return f"the archive expands past {MAX_EXPANDED_BYTES // (1024 * 1024)} MiB; not opened"


def _extract(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    staging: Staging,
    upload_id: str,
    name: str,
    room: int,
) -> Received:
    """One entry into a ``.part`` file, counting what is really decompressed, not the size the
    archive declares."""
    file_id = new_id()
    digest = hashlib.sha256()
    size = 0
    reason: str | None = None
    with staging.create(upload_id, file_id) as sink:
        try:
            with zf.open(info) as source:
                while chunk := source.read(CHUNK):
                    size += len(chunk)
                    if size > MAX_BYTES:
                        reason = f"over {MAX_BYTES} bytes when expanded; the limit is {MAX_BYTES}"
                        break
                    if size > room:
                        reason = _expanded_past()
                        break
                    digest.update(chunk)
                    sink.write(chunk)
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError):
            # CRC or length mismatch, overlapping entries, truncated data, unknown method.
            reason = "damaged or unreadable in the archive"
    if reason is None:
        reason = _content_refusal(staging, upload_id, file_id, size)
    if reason is not None:
        staging.remove(upload_id, file_id)
        return Received(file_id, name, size, None, reason)
    return Received(file_id, name, size, digest.hexdigest())

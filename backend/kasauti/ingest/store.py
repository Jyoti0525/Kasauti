"""Uploads in the database, and keeping the staging area tidy (TODO M2.04).

An upload is open while files are added, then started: one audit job per accepted file, queued
in the same transaction that closes the upload, so it is never half-started. Grouping files
into devices (M2.06) and pairing companion files (M2.05) will change what one job covers; the
upload flow stays the same.

Every change runs with the upload's row locked (``FOR UPDATE`` on PostgreSQL; SQLite's
``BEGIN IMMEDIATE`` locks the whole database), so two requests adding files at once can't
together pass a limit that each checked alone.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Connection, Engine, and_, delete, func, insert, select, update

from kasauti.ingest.staging import Staging
from kasauti.ingest.table import UploadState, upload_files, uploads
from kasauti.ingest.upload import Received, new_id
from kasauti.jobs.queue import JobQueue, utcnow
from kasauti.jobs.table import JobState, jobs

AUDIT_KIND = "audit_file"
"""The job kind that audits one uploaded file (``kasauti.jobs.kinds``)."""
MAX_FILES = 1000
"""Accepted files per upload."""
MAX_ENTRIES = 2 * MAX_FILES
"""Rows per upload, refused ones included: more requests are then turned away."""
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
"""Bytes of accepted files per upload, all waiting on disk until audited."""
OPEN_TTL = dt.timedelta(hours=1)
"""An upload left open this long after its last change expires and its files are deleted."""


class UploadNotFoundError(LookupError):
    pass


class UploadStateError(Exception):
    """The upload can't take this action now (already started, say). User-safe text."""


@dataclass(frozen=True, slots=True)
class FileView:
    id: str
    name: str
    size: int
    sha256: str | None
    accepted: bool
    reason: str | None
    job_id: str | None
    job_state: JobState | None
    job_error: str | None


@dataclass(frozen=True, slots=True)
class UploadView:
    id: str
    label: str | None
    state: UploadState
    frameworks: tuple[str, ...]
    vendor: str | None
    created_at: dt.datetime
    touched_at: dt.datetime
    started_at: dt.datetime | None
    files: tuple[FileView, ...]


class UploadStore:
    def __init__(self, engine: Engine, staging: Staging) -> None:
        self.engine = engine
        self.staging = staging

    # -- reading ------------------------------------------------------------------------------

    def get(self, upload_id: str) -> UploadView | None:
        with self.engine.connect() as conn:
            head = conn.execute(select(uploads).where(uploads.c.id == upload_id)).mappings().first()
            if head is None:
                return None
            rows = conn.execute(
                select(upload_files, jobs.c.state.label("job_state"), jobs.c.error.label("job_err"))
                .select_from(upload_files.outerjoin(jobs, upload_files.c.job_id == jobs.c.id))
                .where(upload_files.c.upload_id == upload_id)
                .order_by(upload_files.c.created_at, upload_files.c.name, upload_files.c.id)
            ).mappings()
            files = tuple(
                FileView(
                    id=r["id"],
                    name=r["name"],
                    size=r["size"],
                    sha256=r["sha256"],
                    accepted=bool(r["accepted"]),
                    reason=r["reason"],
                    job_id=r["job_id"],
                    job_state=None if r["job_state"] is None else JobState(r["job_state"]),
                    job_error=r["job_err"],
                )
                for r in rows
            )
        return UploadView(
            id=head["id"],
            label=head["label"],
            state=UploadState(head["state"]),
            frameworks=tuple(json.loads(head["frameworks"])),
            vendor=head["vendor"],
            created_at=head["created_at"],
            touched_at=head["touched_at"],
            started_at=head["started_at"],
            files=files,
        )

    # -- changes ------------------------------------------------------------------------------

    def create(
        self,
        *,
        label: str | None,
        frameworks: Sequence[str],
        vendor: str | None,
        now: dt.datetime | None = None,
    ) -> str:
        upload_id = new_id()
        now = now or utcnow()
        with self.engine.begin() as conn:
            conn.execute(
                insert(uploads).values(
                    id=upload_id,
                    label=label,
                    state=UploadState.OPEN,
                    frameworks=json.dumps(list(frameworks)),
                    vendor=vendor,
                    created_at=now,
                    touched_at=now,
                )
            )
        return upload_id

    def check_open(self, upload_id: str) -> None:
        """Before receiving a file: the upload exists, is open and has room for more rows."""
        with self.engine.connect() as conn:
            state: str | None = conn.execute(
                select(uploads.c.state).where(uploads.c.id == upload_id)
            ).scalar_one_or_none()
            if state is None:
                raise UploadNotFoundError(upload_id)
            _require_open(state)
            entries = conn.execute(
                select(func.count()).where(upload_files.c.upload_id == upload_id)
            ).scalar_one()
        if entries >= MAX_ENTRIES:
            raise UploadStateError(f"this upload already lists {entries} files; start a new one")

    def add(
        self, upload_id: str, received: Sequence[Received], *, now: dt.datetime | None = None
    ) -> list[Received]:
        """Record files taken in by :func:`kasauti.ingest.upload.inspect`. Limits and duplicate
        content are checked here, with the upload locked; a file refused here is deleted. The
        files as recorded (refusals included)."""
        now = now or utcnow()
        try:
            with self.engine.begin() as conn:
                _require_open(_lock(conn, upload_id))
                recorded = self._limit(conn, upload_id, received)
                if recorded:
                    conn.execute(
                        insert(upload_files),
                        [
                            {
                                "id": r.id,
                                "upload_id": upload_id,
                                "name": r.name,
                                "size": r.size,
                                "sha256": r.sha256,
                                "accepted": r.accepted,
                                "reason": r.reason,
                                "created_at": now,
                            }
                            for r in recorded
                        ],
                    )
                conn.execute(
                    update(uploads).where(uploads.c.id == upload_id).values(touched_at=now)
                )
        except BaseException:
            for r in received:
                self.staging.remove(upload_id, r.id)
            raise
        for r in recorded:
            if r.accepted:
                self.staging.commit(upload_id, r.id)
            else:
                self.staging.remove(upload_id, r.id)
        return recorded

    def remove_file(self, upload_id: str, file_id: str, *, now: dt.datetime | None = None) -> bool:
        """Take a file out of an open upload. False if the upload doesn't list it."""
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            gone = conn.execute(
                delete(upload_files).where(
                    upload_files.c.upload_id == upload_id, upload_files.c.id == file_id
                )
            ).rowcount
            conn.execute(
                update(uploads).where(uploads.c.id == upload_id).values(touched_at=now or utcnow())
            )
        self.staging.remove(upload_id, file_id)
        return gone == 1

    def discard(self, upload_id: str, *, now: dt.datetime | None = None) -> None:
        """Throw away an open upload and its files."""
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            conn.execute(
                update(uploads)
                .where(uploads.c.id == upload_id)
                .values(state=UploadState.DISCARDED, touched_at=now or utcnow())
            )
        self.staging.remove_upload(upload_id)

    def start(
        self, upload_id: str, queue: JobQueue, *, packs: Path, now: dt.datetime | None = None
    ) -> list[str]:
        """Close the upload and queue one audit job per accepted file; the job ids."""
        now = now or utcnow()
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            head = conn.execute(
                select(uploads.c.frameworks, uploads.c.vendor).where(uploads.c.id == upload_id)
            ).one()
            accepted = conn.execute(
                select(upload_files.c.id, upload_files.c.name)
                .where(upload_files.c.upload_id == upload_id, upload_files.c.accepted)
                .order_by(upload_files.c.created_at, upload_files.c.name, upload_files.c.id)
            ).all()
            if not accepted:
                raise UploadStateError("nothing to audit: no file in this upload was accepted")
            job_ids = []
            for row in accepted:
                payload = {
                    "upload": upload_id,
                    "file": row.id,
                    "name": row.name,
                    "frameworks": json.loads(head.frameworks),
                    "vendor": head.vendor,
                    "staging": str(self.staging.root.resolve()),
                    "packs": str(packs.resolve()),
                }
                job_id = queue.enqueue(AUDIT_KIND, payload, now=now, conn=conn)
                conn.execute(
                    update(upload_files).where(upload_files.c.id == row.id).values(job_id=job_id)
                )
                job_ids.append(job_id)
            conn.execute(
                update(uploads)
                .where(uploads.c.id == upload_id)
                .values(state=UploadState.STARTED, started_at=now, touched_at=now)
            )
        return job_ids

    # -- housekeeping -------------------------------------------------------------------------

    def housekeep(self, *, now: dt.datetime | None = None) -> int:
        """Expire uploads left open past :data:`OPEN_TTL`, then delete every staged file nothing
        still needs. How many files were deleted."""
        now = now or utcnow()
        with self.engine.begin() as conn:
            conn.execute(
                update(uploads)
                .where(uploads.c.state == UploadState.OPEN, uploads.c.touched_at < now - OPEN_TTL)
                .values(state=UploadState.EXPIRED)
            )
        removed = 0
        for upload_id in list(self.staging.uploads()):
            # List the files before asking which are needed: a file committed in between is
            # then in the answer, never deleted by mistake.
            staged = list(self.staging.files(upload_id))
            state, needed = self._needed(upload_id)
            if state not in {UploadState.OPEN, UploadState.STARTED}:
                removed += len(staged)
                self.staging.remove_upload(upload_id)
                continue
            for file_id, part, mtime in staged:
                if part:
                    # Still arriving, unless the upload has closed or it has sat too long.
                    stale = time.time() - mtime > OPEN_TTL.total_seconds()
                    if state is UploadState.OPEN and not stale:
                        continue
                elif file_id in needed:
                    continue
                try:
                    self.staging.remove(upload_id, file_id)
                except OSError:  # held open (Windows) by a request still writing it
                    continue
                removed += 1
            if state is UploadState.STARTED and not needed:
                self.staging.remove_upload(upload_id)
        return removed

    def _needed(self, upload_id: str) -> tuple[UploadState | None, set[str]]:
        """The upload's state, and the accepted files still waiting for their audit."""
        with self.engine.connect() as conn:
            state: str | None = conn.execute(
                select(uploads.c.state).where(uploads.c.id == upload_id)
            ).scalar_one_or_none()
            if state is None:
                return None, set()
            query = select(upload_files.c.id).where(
                upload_files.c.upload_id == upload_id, upload_files.c.accepted
            )
            if state == UploadState.STARTED:
                query = query.join(jobs, upload_files.c.job_id == jobs.c.id).where(
                    jobs.c.state.in_([JobState.QUEUED, JobState.RUNNING])
                )
            return UploadState(state), set(conn.execute(query).scalars())

    @staticmethod
    def _limit(conn: Connection, upload_id: str, received: Sequence[Received]) -> list[Received]:
        """``received`` with the per-upload limits and duplicate content applied."""
        mine = and_(upload_files.c.upload_id == upload_id, upload_files.c.accepted)
        count, size = conn.execute(
            select(func.count(), func.coalesce(func.sum(upload_files.c.size), 0)).where(mine)
        ).one()
        seen: dict[str, str] = dict(
            conn.execute(select(upload_files.c.sha256, upload_files.c.name).where(mine)).all()
        )
        out: list[Received] = []
        for r in received:
            reason = r.reason
            if reason is None and r.sha256 in seen:
                reason = f"the same content as {seen[r.sha256]}"
            elif reason is None and count >= MAX_FILES:
                reason = f"the upload already has {MAX_FILES} files; start another for the rest"
            elif reason is None and size + r.size > MAX_UPLOAD_BYTES:
                reason = f"the upload would pass {MAX_UPLOAD_BYTES // 1024**3} GiB; start another"
            if reason is None:
                count, size = count + 1, size + r.size
                seen[str(r.sha256)] = r.name
                out.append(r)
            else:
                out.append(Received(r.id, r.name, r.size, r.sha256, reason))
        return out


def _lock(conn: Connection, upload_id: str) -> str:
    state: str | None = conn.execute(
        select(uploads.c.state).where(uploads.c.id == upload_id).with_for_update()
    ).scalar_one_or_none()
    if state is None:
        raise UploadNotFoundError(upload_id)
    return str(state)


def _require_open(state: str) -> None:
    if state != UploadState.OPEN:
        raise UploadStateError(
            {
                UploadState.STARTED: "this upload has started; start a new one to add files",
                UploadState.DISCARDED: "this upload was discarded",
                UploadState.EXPIRED: "this upload expired unstarted; its files were deleted",
            }.get(UploadState(state), f"this upload is {state}")
        )

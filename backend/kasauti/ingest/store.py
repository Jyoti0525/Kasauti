"""Uploads in the database, and keeping the staging area tidy (TODO M2.04, M2.06).

An upload is open while files are added, then started. As files arrive they are recognised in
a worker (a ``sort_files`` job, :mod:`kasauti.ingest.sort`): configuration or command output,
vendor, hostname. Files added while that job is still queued join it, so a hundred files
dropped one by one cost one or two worker start-ups, not a hundred. If a job fails (a worker
killed for memory or time, or crashed, by one hostile file), it is split and its files
recognised again in smaller jobs, until the file that fails it fails alone: the others are
still grouped. From what it finds, the files are grouped into devices
(:mod:`kasauti.ingest.devices`), which the user can correct by hand, and for each device the
user can type details no file gives, such as its serial number (:mod:`kasauti.identity.manual`).
Starting queues one audit job per device, its configuration and its command outputs together,
in the same transaction that closes the upload, so it is never half-started.

Every change runs with the upload's row locked (``FOR UPDATE`` on PostgreSQL; SQLite's
``BEGIN IMMEDIATE`` locks the whole database), so two requests adding files at once can't
together pass a limit that each checked alone.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import time
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, and_, delete, func, insert, select, update

from kasauti.identity.manual import ManualEntryError, clean_entered
from kasauti.ingest.devices import (
    MAX_COMPANIONS,
    Kind,
    Member,
    Placement,
    Recognised,
    group,
)
from kasauti.ingest.sort import clean_hostname
from kasauti.ingest.staging import Staging
from kasauti.ingest.table import UploadState, upload_files, uploads
from kasauti.ingest.upload import Received, new_id
from kasauti.jobs.queue import JobQueue, utcnow
from kasauti.jobs.results import ResultError, decode_result
from kasauti.jobs.table import JobState, jobs

AUDIT_KIND = "audit_file"
"""The job kind that audits one device (``kasauti.jobs.kinds``)."""
SORT_KIND = "sort_files"
"""The job kind that recognises uploaded files (TODO M2.06)."""
MAX_FILES = 1000
"""Accepted files per upload."""
MAX_ENTRIES = 2 * MAX_FILES
"""Rows per upload, refused ones included: more requests are then turned away."""
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
"""Bytes of accepted files per upload, all waiting on disk until audited."""
OPEN_TTL = dt.timedelta(hours=1)
"""An upload left open this long after its last change expires and its files are deleted."""
AUDIT_TIMEOUT_S = 120
AUDIT_TIMEOUT_PER_MIB_S = 60
"""An audit job's wall-clock limit: a base for start-up and the knowledge base, plus this per
MiB of the file. Measured 2026-09-27 on the plan's laptop: 14 s per MiB for a typical dense
configuration and 44 s per MiB for the densest input found, so a file at the 20 MiB limit gets
22 minutes against 15 at worst. A timeout catches a hang, never a large file. A sort job gets
the same for the files it covers: it parses each configuration, though only for its hostname."""
SORT_RESULT_LIMIT = 16 * 1024 * 1024
"""Bytes a sort job's result may expand to: a line or two per file, 1,000 files at most."""
SPLIT_WAYS = 16
"""A failed sort job that covered several files is split into at most this many, and so on:
one file that fails every job it is in costs 1,000 files three more rounds of jobs, 36 jobs at
most, and is then the only one not recognised."""


class UploadNotFoundError(LookupError):
    pass


class FileNotInUploadError(LookupError):
    pass


class UploadStateError(Exception):
    """The upload can't take this action now (already started, say). User-safe text."""


class PairingError(ValueError):
    """A pairing that can't be made (a configuration with a configuration, say). User-safe."""


class Recognition(StrEnum):
    """Where recognising a file has got to."""

    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"
    """A sort job failed with it alone (or after a restart, when no file can be read): it is
    treated as not recognised, and audited on its own, which says why."""


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
    recognition: Recognition | None = None
    """None for a refused file."""
    recognised: Recognised | None = None
    placement: Placement | None = None
    manual: bool = False
    entered: dict[str, str] = field(default_factory=dict)
    """Device details typed by hand, for a file that is a device (M2.19)."""


@dataclass(frozen=True, slots=True)
class DeviceView:
    """A device as grouped: a configuration and the command outputs that go with it."""

    config: str
    """The configuration's file id."""
    name: str
    vendor: str | None
    hostname: str | None
    companions: tuple[str, ...]
    """File ids."""
    entered: dict[str, str] = field(default_factory=dict)
    """Details typed by hand (M2.19)."""


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
    devices: tuple[DeviceView, ...] = ()

    @property
    def recognising(self) -> int:
        """Accepted files still being recognised: the upload can't start until this is 0."""
        return sum(f.recognition is Recognition.PENDING for f in self.files)


@dataclass(frozen=True, slots=True)
class UploadBrief:
    """An upload in a list: no files, only how many, and where its audits are."""

    id: str
    label: str | None
    state: UploadState
    frameworks: tuple[str, ...]
    vendor: str | None
    created_at: dt.datetime
    started_at: dt.datetime | None
    accepted: int
    refused: int
    audits: dict[str, int]
    """Audit jobs by state (``queued``, ``running``, ``succeeded``…)."""


@dataclass(frozen=True, slots=True)
class AuditJob:
    """One device's audit: the job and the upload it came from."""

    job_id: str
    upload_id: str
    label: str | None
    name: str
    """The configuration's display name."""
    state: JobState
    error: str | None
    created_at: dt.datetime
    finished_at: dt.datetime | None


def audit_timeout(size: int) -> int:
    """Seconds an audit of ``size`` bytes may take (:data:`AUDIT_TIMEOUT_PER_MIB_S`)."""
    return AUDIT_TIMEOUT_S + math.ceil(AUDIT_TIMEOUT_PER_MIB_S * size / (1024 * 1024))


class UploadStore:
    def __init__(self, engine: Engine, staging: Staging, queue: JobQueue, packs: Path) -> None:
        self.engine = engine
        self.staging = staging
        self.queue = queue
        self.packs = packs

    # -- reading ------------------------------------------------------------------------------

    def get(self, upload_id: str) -> UploadView | None:
        """The upload as it stands. A failed sort job found here is split first (see
        :meth:`_split_failed`): a repair under the upload's lock, done once by whoever reads
        first, so the files it covered never show as failed while they can still be
        recognised."""
        view, failed = self._view(upload_id)
        if failed:
            with self.engine.begin() as conn:
                if _lock(conn, upload_id) == UploadState.OPEN:
                    self._split_failed(conn, upload_id, utcnow())
            view, _ = self._view(upload_id)
        return view

    def recent(self, limit: int = 100) -> list[UploadBrief]:
        """The newest uploads first, discarded ones left out."""
        with self.engine.connect() as conn:
            heads = (
                conn.execute(
                    select(uploads)
                    .where(uploads.c.state != UploadState.DISCARDED)
                    .order_by(uploads.c.created_at.desc(), uploads.c.id)
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            ids = [h["id"] for h in heads]
            files: dict[tuple[str, bool], int] = {
                (u, bool(a)): n
                for u, a, n in conn.execute(
                    select(upload_files.c.upload_id, upload_files.c.accepted, func.count())
                    .where(upload_files.c.upload_id.in_(ids))
                    .group_by(upload_files.c.upload_id, upload_files.c.accepted)
                ).all()
            }
            audits: dict[str, dict[str, int]] = {}
            # A device's command outputs share its job: count each job once.
            for u, state, _job in conn.execute(
                select(upload_files.c.upload_id, jobs.c.state, jobs.c.id)
                .join(jobs, upload_files.c.job_id == jobs.c.id)
                .where(upload_files.c.upload_id.in_(ids))
                .distinct()
            ).all():
                counts = audits.setdefault(u, {})
                counts[state] = counts.get(state, 0) + 1
        return [
            UploadBrief(
                id=h["id"],
                label=h["label"],
                state=UploadState(h["state"]),
                frameworks=tuple(json.loads(h["frameworks"])),
                vendor=h["vendor"],
                created_at=h["created_at"],
                started_at=h["started_at"],
                accepted=files.get((h["id"], True), 0),
                refused=files.get((h["id"], False), 0),
                audits=audits.get(h["id"], {}),
            )
            for h in heads
        ]

    def audit_jobs(self, *, upload_id: str | None = None, limit: int = 1000) -> list[AuditJob]:
        """Device audits, newest first and then by name: every upload's, or one upload's."""
        query = select(
            jobs.c.id,
            jobs.c.state,
            jobs.c.error,
            jobs.c.created_at,
            jobs.c.finished_at,
            jobs.c.payload,
        ).where(jobs.c.kind == AUDIT_KIND)
        if upload_id is not None:
            mine = select(upload_files.c.job_id).where(upload_files.c.upload_id == upload_id)
            query = query.where(jobs.c.id.in_(mine))
        query = query.order_by(jobs.c.created_at.desc(), jobs.c.id).limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
            payloads = [json.loads(r["payload"]) for r in rows]
            labels: dict[str, str | None] = dict(
                conn.execute(
                    select(uploads.c.id, uploads.c.label).where(
                        uploads.c.id.in_({str(p["upload"]) for p in payloads})
                    )
                ).all()
            )
        found = [
            AuditJob(
                job_id=r["id"],
                upload_id=str(p["upload"]),
                label=labels.get(str(p["upload"])),
                name=str(p["name"]),
                state=JobState(r["state"]),
                error=r["error"],
                created_at=r["created_at"],
                finished_at=r["finished_at"],
            )
            for r, p in zip(rows, payloads, strict=True)
        ]
        # An upload's audits are queued together: by name within the same moment.
        found.sort(key=lambda a: a.name)
        found.sort(key=lambda a: a.created_at, reverse=True)
        return found

    def _view(self, upload_id: str) -> tuple[UploadView | None, bool]:
        """The upload, and whether a sort job of it has failed and should be split."""
        with self.engine.connect() as conn:
            head = conn.execute(select(uploads).where(uploads.c.id == upload_id)).mappings().first()
            if head is None:
                return None, False
            rows = (
                conn.execute(
                    select(
                        upload_files,
                        jobs.c.state.label("job_state"),
                        jobs.c.error.label("job_err"),
                    )
                    .select_from(upload_files.outerjoin(jobs, upload_files.c.job_id == jobs.c.id))
                    .where(upload_files.c.upload_id == upload_id)
                    .order_by(upload_files.c.created_at, upload_files.c.name, upload_files.c.id)
                )
                .mappings()
                .all()
            )
            is_open = head["state"] == UploadState.OPEN
            found, failed = _recognitions(conn, rows, self.staging.key_id if is_open else None)
        members = [_member(r, found) for r in rows if r["accepted"]]
        placements = group(members)
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
                recognition=found[r["id"]][0] if r["accepted"] else None,
                recognised=found[r["id"]][1] if r["accepted"] else None,
                placement=placements.get(r["id"]),
                manual=bool(r["manual"]),
                entered=_entered(r["entered"]),
            )
            for r in rows
        )
        view = UploadView(
            id=head["id"],
            label=head["label"],
            state=UploadState(head["state"]),
            frameworks=tuple(json.loads(head["frameworks"])),
            vendor=head["vendor"],
            created_at=head["created_at"],
            touched_at=head["touched_at"],
            started_at=head["started_at"],
            files=files,
            devices=_devices(members, placements, {r["id"]: _entered(r["entered"]) for r in rows}),
        )
        return view, bool(failed)

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
        """Record files taken in by :func:`kasauti.ingest.upload.inspect`, and queue the
        accepted ones to be recognised. Limits and duplicate content are checked here, with the
        upload locked; a file refused here is deleted. The files as recorded (refusals
        included)."""
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
                self._sort(conn, upload_id, [r.id for r in recorded if r.accepted], now)
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
        """Take a file out of an open upload. False if the upload doesn't list it. Command
        outputs paired with it by hand go back to being paired automatically."""
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            gone = conn.execute(
                delete(upload_files).where(
                    upload_files.c.upload_id == upload_id, upload_files.c.id == file_id
                )
            ).rowcount
            conn.execute(
                update(upload_files)
                .where(upload_files.c.upload_id == upload_id, upload_files.c.paired_with == file_id)
                .values(manual=False, paired_with=None)
            )
            conn.execute(
                update(uploads).where(uploads.c.id == upload_id).values(touched_at=now or utcnow())
            )
        self.staging.remove(upload_id, file_id)
        return gone == 1

    def pair(
        self,
        upload_id: str,
        file_id: str,
        config_id: str | None,
        *,
        now: dt.datetime | None = None,
    ) -> None:
        """Pair a command output with a configuration by hand, or (``config_id`` None) leave
        it out of every audit. :class:`PairingError` if that can't be done."""
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            members = self._members(conn, upload_id)
            me = _find(members, file_id)
            if me.recognised is None:
                raise UploadStateError(f"{me.name} is still being recognised; try again shortly")
            if me.recognised.kind is not Kind.COMPANION:
                what = (
                    "a configuration, which is a device of its own"
                    if me.recognised.kind is Kind.CONFIG
                    else "not recognised as a command output, so no audit could use it"
                )
                raise PairingError(f"only command outputs are paired; {me.name} is {what}")
            if config_id is not None:
                _check_target(members, me, me.recognised, config_id)
            conn.execute(
                update(upload_files)
                .where(upload_files.c.id == file_id)
                .values(manual=True, paired_with=config_id)
            )
            conn.execute(
                update(uploads).where(uploads.c.id == upload_id).values(touched_at=now or utcnow())
            )

    def unpair(self, upload_id: str, file_id: str, *, now: dt.datetime | None = None) -> None:
        """Undo :meth:`pair`: the file's device is found automatically again."""
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            done = conn.execute(
                update(upload_files)
                .where(
                    upload_files.c.upload_id == upload_id,
                    upload_files.c.id == file_id,
                    upload_files.c.accepted,
                )
                .values(manual=False, paired_with=None)
            ).rowcount
            if done != 1:
                raise FileNotInUploadError(file_id)
            conn.execute(
                update(uploads).where(uploads.c.id == upload_id).values(touched_at=now or utcnow())
            )

    def enter(
        self,
        upload_id: str,
        file_id: str,
        values: dict[str, object],
        *,
        now: dt.datetime | None = None,
    ) -> None:
        """Set the details typed by hand for the device ``file_id`` is (its configuration, or a
        file audited alone), replacing any set before; ``{}`` clears them.
        :class:`ManualEntryError` if they can't be taken, or the file is not a device."""
        entered = clean_entered(values)
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            members = self._members(conn, upload_id)
            me = _find(members, file_id)
            if me.recognised is None:
                raise UploadStateError(f"{me.name} is still being recognised; try again shortly")
            if group(members)[file_id].device != file_id:
                raise ManualEntryError(
                    f"{me.name} is a command output, not a device: enter the details on the "
                    "configuration of the device it comes from"
                )
            conn.execute(
                update(upload_files)
                .where(upload_files.c.id == file_id)
                .values(entered=json.dumps(entered) if entered else None)
            )
            conn.execute(
                update(uploads).where(uploads.c.id == upload_id).values(touched_at=now or utcnow())
            )

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

    def start(self, upload_id: str, *, now: dt.datetime | None = None) -> list[str]:
        """Close the upload and queue one audit job per device; the job ids.
        :class:`UploadStateError` while files are still being recognised."""
        now = now or utcnow()
        waiting = 0
        with self.engine.begin() as conn:
            _require_open(_lock(conn, upload_id))
            head = conn.execute(
                select(uploads.c.frameworks, uploads.c.vendor).where(uploads.c.id == upload_id)
            ).one()
            self._split_failed(conn, upload_id, now)
            members = self._members(conn, upload_id)
            if not members:
                raise UploadStateError("nothing to audit: no file in this upload was accepted")
            # Files with no sort job (an upload open across the upgrade that added them).
            unsorted: list[str] = list(
                conn.execute(
                    select(upload_files.c.id).where(
                        upload_files.c.upload_id == upload_id,
                        upload_files.c.accepted,
                        upload_files.c.sort_job_id.is_(None),
                    )
                ).scalars()
            )
            self._sort(conn, upload_id, unsorted, now)
            waiting = sum(m.recognised is None for m in members)
            job_ids = [] if waiting else self._queue_audits(conn, upload_id, head, members, now)
        if waiting:
            raise UploadStateError(
                f"{waiting} file{'s are' if waiting > 1 else ' is'} still being recognised; "
                "start again when they are"
            )
        return job_ids

    def _queue_audits(
        self,
        conn: Connection,
        upload_id: str,
        head: Any,
        members: Sequence[Member],
        now: dt.datetime,
    ) -> list[str]:
        placements = group(members)
        sizes: dict[str, int] = {}
        entered: dict[str, dict[str, str]] = {}
        for file_id, size, typed in conn.execute(
            select(upload_files.c.id, upload_files.c.size, upload_files.c.entered).where(
                upload_files.c.upload_id == upload_id
            )
        ).all():
            sizes[file_id] = size
            entered[file_id] = _entered(typed)
        by_id = {m.id: m for m in members}
        roots = [m for m in members if placements[m.id].device == m.id]
        if not roots:
            raise UploadStateError(
                "nothing to audit: every file here is a command output, and each needs its "
                "device's configuration in the same upload"
            )
        job_ids = []
        for root in roots:
            paired = sorted(
                (by_id[i] for i, p in placements.items() if p.device == root.id and i != root.id),
                key=lambda m: (m.name, m.id),
            )
            payload = {
                "upload": upload_id,
                "file": root.id,
                "name": root.name,
                "companions": [{"id": m.id, "name": m.name} for m in paired],
                "entered": entered[root.id],
                "frameworks": json.loads(head.frameworks),
                "vendor": head.vendor,
                "staging": str(self.staging.root.resolve()),
                "staging_key": self.staging.key_id,
                "packs": str(self.packs.resolve()),
            }
            size = sizes[root.id] + sum(sizes[m.id] for m in paired)
            job_id = self.queue.enqueue(
                AUDIT_KIND, payload, timeout_s=audit_timeout(size), now=now, conn=conn
            )
            conn.execute(
                update(upload_files)
                .where(upload_files.c.id.in_([root.id, *(m.id for m in paired)]))
                .values(job_id=job_id)
            )
            job_ids.append(job_id)
        conn.execute(
            update(uploads)
            .where(uploads.c.id == upload_id)
            .values(state=UploadState.STARTED, started_at=now, touched_at=now)
        )
        return job_ids

    # -- recognising --------------------------------------------------------------------------

    def _sort(
        self, conn: Connection, upload_id: str, file_ids: Collection[str], now: dt.datetime
    ) -> None:
        """Queue ``file_ids`` to be recognised: added to a sort job of this upload that is still
        queued, else to a new one. Runs with the upload locked, so only this request adds to
        it. One job at most is queued, unless a failed one was just split."""
        if not file_ids:
            return
        queued = conn.execute(
            select(jobs.c.id, jobs.c.payload)
            .select_from(upload_files.join(jobs, upload_files.c.sort_job_id == jobs.c.id))
            .where(upload_files.c.upload_id == upload_id, jobs.c.state == JobState.QUEUED)
            .limit(1)
        ).first()
        new = list(file_ids)
        job_id: str | None = None
        if queued is not None:
            payload = json.loads(queued.payload)
            # From the rows, not the old payload: files taken back out since drop off, so the
            # payload never grows past the files the upload really has.
            payload["files"] = [
                *conn.execute(
                    select(upload_files.c.id)
                    .where(upload_files.c.sort_job_id == queued.id)
                    .order_by(upload_files.c.created_at, upload_files.c.id)
                ).scalars(),
                *new,
            ]
            if self.queue.amend(
                queued.id, payload, timeout_s=self._sort_timeout(conn, payload["files"]), conn=conn
            ):
                job_id = queued.id
        if job_id is None:
            self._new_sort_job(conn, upload_id, new, now)
        else:
            conn.execute(
                update(upload_files).where(upload_files.c.id.in_(new)).values(sort_job_id=job_id)
            )

    def _new_sort_job(
        self, conn: Connection, upload_id: str, file_ids: list[str], now: dt.datetime
    ) -> None:
        vendor: str | None = conn.execute(
            select(uploads.c.vendor).where(uploads.c.id == upload_id)
        ).scalar_one()
        payload = {
            "upload": upload_id,
            "files": file_ids,
            "vendor": vendor,
            "staging": str(self.staging.root.resolve()),
            "staging_key": self.staging.key_id,
            "packs": str(self.packs.resolve()),
        }
        job_id = self.queue.enqueue(
            SORT_KIND, payload, timeout_s=self._sort_timeout(conn, file_ids), now=now, conn=conn
        )
        conn.execute(
            update(upload_files).where(upload_files.c.id.in_(file_ids)).values(sort_job_id=job_id)
        )

    def _split_failed(self, conn: Connection, upload_id: str, now: dt.datetime) -> None:
        """Queue the files of each failed sort job again, in up to :data:`SPLIT_WAYS` smaller
        jobs. A handler error on one file doesn't fail a job (:mod:`kasauti.ingest.sort`), so
        a job fails only when its worker is killed or crashes, and any of its files may be the
        cause: splitting until that file fails alone keeps the others recognised. Not after a
        restart: no file of the job can be read then, alone or not. Runs with the upload
        locked, and leaves its expiry alone, since a read that finds a failed job does this
        too."""
        rows = (
            conn.execute(
                select(upload_files)
                .where(upload_files.c.upload_id == upload_id, upload_files.c.accepted)
                .order_by(upload_files.c.created_at, upload_files.c.name, upload_files.c.id)
            )
            .mappings()
            .all()
        )
        _, failed = _recognitions(conn, rows, self.staging.key_id)
        for job_id in sorted(failed):
            ids = [r["id"] for r in rows if r["sort_job_id"] == job_id]
            size = math.ceil(len(ids) / SPLIT_WAYS)
            for start in range(0, len(ids), size):
                self._new_sort_job(conn, upload_id, ids[start : start + size], now)

    @staticmethod
    def _sort_timeout(conn: Connection, file_ids: Iterable[str]) -> int:
        size = 0
        ids = list(file_ids)
        for start in range(0, len(ids), 500):  # keep each IN list short
            size += conn.execute(
                select(func.coalesce(func.sum(upload_files.c.size), 0)).where(
                    upload_files.c.id.in_(ids[start : start + 500])
                )
            ).scalar_one()
        return audit_timeout(size)

    def _members(self, conn: Connection, upload_id: str) -> list[Member]:
        rows = (
            conn.execute(
                select(upload_files)
                .where(upload_files.c.upload_id == upload_id, upload_files.c.accepted)
                .order_by(upload_files.c.created_at, upload_files.c.name, upload_files.c.id)
            )
            .mappings()
            .all()
        )
        found, _ = _recognitions(conn, rows, self.staging.key_id)
        return [_member(r, found) for r in rows]

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
        """The upload's state, and the accepted files still waiting for their audit: once it
        has started, a device's command outputs wait with its configuration, under its job;
        an output left out of every audit is needed by none."""
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


# -- recognitions --------------------------------------------------------------------------------


def _recognitions(
    conn: Connection, rows: Sequence[Any], key_id: str | None
) -> tuple[dict[str, tuple[Recognition, Recognised | None]], set[str]]:
    """For each accepted file, how far recognising it has got and what it found; and the
    failed sort jobs to split (:meth:`UploadStore._split_failed`), whose files count as still
    pending. With ``key_id`` None (an upload no longer open), there are none. A sort job's
    result comes from a worker that has read untrusted files, so it is checked like input: an
    entry for a file the job wasn't given, or that isn't well formed, is ignored."""
    accepted = [r for r in rows if r["accepted"]]
    job_ids = {r["sort_job_id"] for r in accepted if r["sort_job_id"] is not None}
    states: dict[str, str] = (
        dict(conn.execute(select(jobs.c.id, jobs.c.state).where(jobs.c.id.in_(job_ids))).all())
        if job_ids
        else {}
    )
    failed = [i for i, state in states.items() if state == JobState.FAILED]
    split: set[str] = set()
    if key_id is not None and failed:
        for job_id, text in conn.execute(
            select(jobs.c.id, jobs.c.payload).where(jobs.c.id.in_(failed))
        ).all():
            payload = json.loads(text)  # written by this server, not by a worker
            if len(payload["files"]) > 1 and payload["staging_key"] == key_id:
                split.add(job_id)
    results: dict[str, dict[str, Recognised]] = {}
    for job_id, job_state in states.items():
        if job_state == JobState.SUCCEEDED:
            given = {r["id"] for r in accepted if r["sort_job_id"] == job_id}
            blob = conn.execute(
                select(jobs.c.result_gzip).where(jobs.c.id == job_id)
            ).scalar_one_or_none()
            results[job_id] = _read_sorted(None if blob is None else bytes(blob), given)
    unknown = Recognised(Kind.UNKNOWN)
    out: dict[str, tuple[Recognition, Recognised | None]] = {}
    for r in accepted:
        sorter: str | None = r["sort_job_id"]
        state: str | None = None if sorter is None else states.get(sorter)
        if state in (None, JobState.QUEUED, JobState.RUNNING) or sorter in split:
            out[r["id"]] = (Recognition.PENDING, None)
        elif state == JobState.SUCCEEDED and sorter is not None:
            out[r["id"]] = (Recognition.DONE, results[sorter].get(r["id"], unknown))
        else:
            out[r["id"]] = (Recognition.FAILED, unknown)
    return out, split


def _read_sorted(blob: bytes | None, given: Collection[str]) -> dict[str, Recognised]:
    if blob is None:
        return {}
    try:
        obj = decode_result(blob, limit=SORT_RESULT_LIMIT)
    except (ResultError, ValueError):
        return {}
    entries = obj.get("files")
    out: dict[str, Recognised] = {}
    for item in entries if isinstance(entries, list) else ():
        if not isinstance(item, dict) or item.get("id") not in given:
            continue
        try:
            kind = Kind(str(item.get("kind")))
        except ValueError:
            continue
        vendor, command = item.get("vendor"), item.get("command")
        out[item["id"]] = Recognised(
            kind=kind,
            vendor=vendor if isinstance(vendor, str) and 0 < len(vendor) <= 64 else None,
            command=command if isinstance(command, str) and 0 < len(command) <= 64 else None,
            hostname=clean_hostname(item.get("hostname")),
        )
    return out


def _member(row: Any, found: dict[str, tuple[Recognition, Recognised | None]]) -> Member:
    return Member(
        id=row["id"],
        name=row["name"],
        recognised=found[row["id"]][1],
        manual=bool(row["manual"]),
        paired_with=row["paired_with"],
    )


def _entered(text: str | None) -> dict[str, str]:
    """A row's details typed by hand, checked again on the way out."""
    if text is None:
        return {}
    try:
        return clean_entered(json.loads(text))
    except (ValueError, TypeError):  # ManualEntryError is a ValueError, as is bad JSON
        return {}


def _devices(
    members: Sequence[Member],
    placements: dict[str, Placement],
    entered: dict[str, dict[str, str]],
) -> tuple[DeviceView, ...]:
    by_id = {m.id: m for m in members}
    out = []
    for m in members:
        r = m.recognised
        if r is None or r.kind is not Kind.CONFIG:
            continue
        paired = sorted(
            (by_id[i] for i, p in placements.items() if p.device == m.id and i != m.id),
            key=lambda c: (c.name, c.id),
        )
        out.append(
            DeviceView(
                config=m.id,
                name=m.name,
                vendor=r.vendor,
                hostname=r.hostname,
                companions=tuple(c.id for c in paired),
                entered=entered.get(m.id, {}),
            )
        )
    return tuple(out)


def _find(members: Sequence[Member], file_id: str) -> Member:
    for m in members:
        if m.id == file_id:
            return m
    raise FileNotInUploadError(file_id)


def _check_target(members: Sequence[Member], me: Member, mine: Recognised, config_id: str) -> None:
    target = _find(members, config_id)
    r = target.recognised
    if r is None or r.kind is not Kind.CONFIG:
        raise PairingError(f"{target.name} isn't a configuration, so it can't take {me.name}")
    if r.vendor != mine.vendor:
        raise PairingError(
            f"{me.name} is {mine.vendor} output and {target.name} a {r.vendor} configuration"
        )
    placements = group(members)
    count = sum(
        1 for i, p in placements.items() if p.device == config_id and i not in (config_id, me.id)
    )
    if count >= MAX_COMPANIONS:
        raise PairingError(f"{target.name} already has {MAX_COMPANIONS} command outputs")


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


__all__ = [
    "AUDIT_KIND",
    "SORT_KIND",
    "SPLIT_WAYS",
    "DeviceView",
    "FileNotInUploadError",
    "FileView",
    "PairingError",
    "Recognition",
    "UploadNotFoundError",
    "UploadStateError",
    "UploadStore",
    "UploadView",
    "audit_timeout",
]

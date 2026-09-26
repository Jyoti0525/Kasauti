"""The job queue's database operations (TODO M2.03).

Every state change is one short transaction, and every change a pool makes is guarded by the
job's current state and holder, so two pools (two ``kasauti serve`` processes sharing a
PostgreSQL database, say) never both run a job, and a pool that lost a job can't overwrite
what its new holder records.

Claiming: on PostgreSQL ``SELECT ... FOR UPDATE SKIP LOCKED``, so pools don't wait on each
other; on SQLite every transaction starts with ``BEGIN IMMEDIATE`` (M2.02), which already
serialises claims.

Lost jobs: a pool renews ``heartbeat_at`` on the jobs it holds. When the pool dies with them
(power cut, killed server), the lease runs out and :meth:`JobQueue.recover` puts them back in the
queue, or fails them once they have used every attempt. A job whose *own* process crashed or
timed out is failed at once, not retried: the same input would do the same again.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, RowMapping, and_, func, insert, select, update

from kasauti.jobs.table import (
    ERROR_LIMIT,
    FINISHED,
    PAYLOAD_LIMIT,
    RESULT_LIMIT,
    JobState,
    jobs,
)

type JsonObject = dict[str, Any]

DEFAULT_TIMEOUT_S = 300
DEFAULT_MAX_ATTEMPTS = 3


class JobInputError(ValueError):
    """A job that can't be queued as given."""


@dataclass(frozen=True, slots=True)
class Job:
    """A job as a client sees it."""

    id: str
    kind: str
    state: JobState
    attempts: int
    created_at: dt.datetime
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    error: str | None
    result: JsonObject | None
    cancel_requested: bool


@dataclass(frozen=True, slots=True)
class Claim:
    """A job a pool has taken and must now run."""

    id: str
    kind: str
    payload: str
    """Canonical JSON, handed to the worker process as is."""
    timeout_s: int


def canonical(obj: JsonObject) -> str:
    """One JSON text per value: sorted keys, no whitespace, no NaN or infinity."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class JobQueue:
    def __init__(self, engine: Engine, kinds: Collection[str]) -> None:
        self.engine = engine
        self.kinds = frozenset(kinds)

    # -- clients ------------------------------------------------------------------------------

    def enqueue(
        self,
        kind: str,
        payload: JsonObject,
        *,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        now: dt.datetime | None = None,
    ) -> str:
        """Queue a job; its id."""
        if kind not in self.kinds:
            raise JobInputError(f"unknown job kind {kind!r}")
        if not isinstance(payload, dict):
            raise JobInputError("a job's payload is a JSON object")
        try:
            text = canonical(payload)
        except (TypeError, ValueError) as err:
            raise JobInputError(f"the payload isn't JSON ({type(err).__name__})") from None
        if len(text.encode()) > PAYLOAD_LIMIT:
            raise JobInputError(
                f"the payload is over {PAYLOAD_LIMIT // 1024} KiB; "
                "pass a reference to stored input, not the input"
            )
        if timeout_s < 1 or max_attempts < 1:
            raise JobInputError("timeout_s and max_attempts must be at least 1")
        job_id = str(uuid.uuid4())
        with self.engine.begin() as conn:
            conn.execute(
                insert(jobs).values(
                    id=job_id,
                    kind=kind,
                    state=JobState.QUEUED,
                    payload=text,
                    attempts=0,
                    max_attempts=max_attempts,
                    timeout_s=timeout_s,
                    cancel_requested=False,
                    created_at=now or utcnow(),
                )
            )
        return job_id

    def get(self, job_id: str) -> Job | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(jobs).where(jobs.c.id == job_id)).mappings().first()
        return None if row is None else _job(row)

    def cancel(self, job_id: str, *, now: dt.datetime | None = None) -> Job | None:
        """Cancel a job: at once if it is queued; a running one is stopped by its pool at its
        next heartbeat. A finished job is left as it is. The job afterwards, or ``None``."""
        with self.engine.begin() as conn:
            conn.execute(
                update(jobs)
                .where(jobs.c.id == job_id, jobs.c.state == JobState.QUEUED)
                .values(state=JobState.CANCELLED, finished_at=now or utcnow())
            )
            conn.execute(
                update(jobs)
                .where(jobs.c.id == job_id, jobs.c.state == JobState.RUNNING)
                .values(cancel_requested=True)
            )
        return self.get(job_id)

    def pending(self) -> int:
        """Queued jobs this queue's kinds cover."""
        with self.engine.connect() as conn:
            return conn.execute(
                select(func.count())
                .select_from(jobs)
                .where(jobs.c.state == JobState.QUEUED, jobs.c.kind.in_(self.kinds))
            ).scalar_one()

    # -- pools --------------------------------------------------------------------------------

    def claim(self, worker: str, limit: int, *, now: dt.datetime | None = None) -> list[Claim]:
        """Take up to ``limit`` of the oldest queued jobs of this queue's kinds for ``worker``."""
        if limit < 1 or not self.kinds:
            return []
        now = now or utcnow()
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(jobs.c.id, jobs.c.kind, jobs.c.payload, jobs.c.timeout_s)
                .where(jobs.c.state == JobState.QUEUED, jobs.c.kind.in_(self.kinds))
                .order_by(jobs.c.created_at, jobs.c.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            ).all()
            if not rows:
                return []
            ids = [r.id for r in rows]
            taken = conn.execute(
                update(jobs)
                .where(jobs.c.id.in_(ids), jobs.c.state == JobState.QUEUED)
                .values(
                    state=JobState.RUNNING,
                    worker=worker,
                    attempts=jobs.c.attempts + 1,
                    started_at=now,
                    heartbeat_at=now,
                )
            )
            # The rows are locked (PostgreSQL) or the database is (SQLite), so all of them move.
            # If not, something else is writing the table: roll back rather than run a job twice.
            if taken.rowcount != len(ids):
                raise RuntimeError("jobs changed while being claimed; nothing was claimed")
        return [Claim(r.id, r.kind, r.payload, r.timeout_s) for r in rows]

    def heartbeat(
        self, worker: str, job_ids: Collection[str], *, now: dt.datetime | None = None
    ) -> tuple[set[str], set[str]]:
        """Renew ``worker``'s lease on ``job_ids``. Returns the ids it no longer holds (another
        pool recovered them; stop running them) and the ids whose cancellation was asked for."""
        if not job_ids:
            return set(), set()
        held = self._held(worker, job_ids)
        with self.engine.begin() as conn:
            conn.execute(update(jobs).where(held).values(heartbeat_at=now or utcnow()))
            rows = conn.execute(select(jobs.c.id, jobs.c.cancel_requested).where(held)).all()
        still = {r.id for r in rows}
        return set(job_ids) - still, {r.id for r in rows if r.cancel_requested}

    def finish(
        self,
        worker: str,
        job_id: str,
        state: JobState,
        *,
        result: JsonObject | None = None,
        error: str | None = None,
        now: dt.datetime | None = None,
    ) -> bool:
        """Record how ``worker``'s run of ``job_id`` ended; False if it no longer held the job."""
        if state not in FINISHED:
            raise ValueError(f"{state} isn't a finished state")
        values: dict[str, Any] = {"state": state, "finished_at": now or utcnow(), "worker": None}
        if result is not None:
            values["result"] = canonical(result)
        if error is not None:
            values["error"] = error[:ERROR_LIMIT]
        with self.engine.begin() as conn:
            done = conn.execute(update(jobs).where(self._held(worker, [job_id])).values(values))
        return done.rowcount == 1

    def release(self, worker: str, job_ids: Collection[str]) -> int:
        """Put jobs back in the queue without counting the attempt: the pool is shutting down,
        which isn't the job's doing. How many were released."""
        if not job_ids:
            return 0
        with self.engine.begin() as conn:
            done = conn.execute(
                update(jobs)
                .where(self._held(worker, job_ids))
                .values(
                    state=JobState.QUEUED,
                    worker=None,
                    attempts=jobs.c.attempts - 1,
                    started_at=None,
                    heartbeat_at=None,
                )
            )
        return done.rowcount

    def recover(self, lease: dt.timedelta, *, now: dt.datetime | None = None) -> list[str]:
        """Jobs whose pool stopped renewing its lease: back to the queue, cancelled if that was
        asked for, or failed once every attempt is used. The ids recovered."""
        now = now or utcnow()
        stale = and_(jobs.c.state == JobState.RUNNING, jobs.c.heartbeat_at < now - lease)
        gone = {"worker": None, "heartbeat_at": None}
        with self.engine.begin() as conn:
            ids: list[str] = list(conn.execute(select(jobs.c.id).where(stale)).scalars())
            conn.execute(
                update(jobs)
                .where(stale, jobs.c.cancel_requested)
                .values(state=JobState.CANCELLED, finished_at=now, **gone)
            )
            conn.execute(
                update(jobs)
                .where(stale, jobs.c.attempts >= jobs.c.max_attempts)
                .values(
                    state=JobState.FAILED,
                    finished_at=now,
                    error="the worker running it was lost on every attempt",
                    **gone,
                )
            )
            conn.execute(
                update(jobs).where(stale).values(state=JobState.QUEUED, started_at=None, **gone)
            )
        return ids

    @staticmethod
    def _held(worker: str, job_ids: Collection[str]) -> Any:
        return and_(
            jobs.c.id.in_(list(job_ids)),
            jobs.c.state == JobState.RUNNING,
            jobs.c.worker == worker,
        )


def _job(row: RowMapping) -> Job:
    return Job(
        id=row["id"],
        kind=row["kind"],
        state=JobState(row["state"]),
        attempts=row["attempts"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        error=row["error"],
        result=None if row["result"] is None else json.loads(row["result"]),
        cancel_requested=bool(row["cancel_requested"]),
    )


__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_S",
    "PAYLOAD_LIMIT",
    "RESULT_LIMIT",
    "Claim",
    "Job",
    "JobInputError",
    "JobQueue",
    "JsonObject",
    "canonical",
    "utcnow",
]

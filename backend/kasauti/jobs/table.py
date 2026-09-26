"""The ``jobs`` table: the queue itself (PLAN §4.2, §19.1 "no broker").

A job holds a *reference* to its input (an upload's hash, a device id), never configuration
text: the payload is capped at :data:`PAYLOAD_LIMIT` bytes, so a whole configuration can't be
passed this way by mistake, and the database keeps only masked text (PLAN §5.2).
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    false,
)

from kasauti.db.schema import Base
from kasauti.db.types import UtcDateTime

PAYLOAD_LIMIT = 64 * 1024
"""Bytes of JSON: enough for references and options, too small for a configuration."""
RESULT_LIMIT = 64 * 1024 * 1024
"""Bytes of *compressed* result a job may return (:mod:`kasauti.jobs.results`). Measured
2026-09-27: an audit's JSON is 31 times its configuration's size and compresses to 0.8 times
it; the densest input found (a bare ``interface`` line after line) compresses to 2.2 times.
So a configuration at the 20 MiB upload limit gives at most about 44 MiB: no file the upload
accepts can fail here."""
RESULT_EXPANDED_LIMIT = 2 * 1024 * 1024 * 1024
"""Bytes a stored result may expand to. The densest input measured expands 92 times its size
(1.8 GiB for 20 MiB); this bounds what a reader of a result must be ready for, and how long
checking one can take."""
ERROR_LIMIT = 500
"""Characters of the error shown for a failed job."""


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


FINISHED = frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED})

_STATES = ", ".join(f"'{s.value}'" for s in JobState)

jobs = Table(
    "jobs",
    Base.metadata,
    Column("id", String(36), primary_key=True, comment="UUID 4; not guessable, not a counter"),
    Column("kind", String(64), nullable=False, comment="a key of kasauti.jobs.kinds.HANDLERS"),
    Column("state", String(16), nullable=False),
    Column("payload", Text, nullable=False, comment="canonical JSON object"),
    Column(
        "result_gzip",
        LargeBinary,
        comment="gzip of the canonical JSON object, once succeeded (kasauti.jobs.results)",
    ),
    Column("error", String(ERROR_LIMIT), comment="why it failed; never configuration text"),
    Column("attempts", Integer, nullable=False, comment="times claimed by a worker"),
    Column("max_attempts", Integer, nullable=False),
    Column("timeout_s", Integer, nullable=False, comment="wall-clock limit per attempt"),
    Column("cancel_requested", Boolean, nullable=False, server_default=false()),
    Column("worker", String(128), comment="the pool holding it while running"),
    Column("created_at", UtcDateTime, nullable=False),
    Column("started_at", UtcDateTime),
    Column("heartbeat_at", UtcDateTime, comment="the holding pool renews it; stale means lost"),
    Column("finished_at", UtcDateTime),
    CheckConstraint(f"state IN ({_STATES})", name="state"),
    CheckConstraint("attempts >= 0 AND attempts <= max_attempts", name="attempts"),
    CheckConstraint("max_attempts >= 1", name="max_attempts"),
    CheckConstraint("timeout_s >= 1", name="timeout_s"),
    # What a pool claims next (oldest queued first), and what the reaper scans.
    Index("ix_jobs_state_created_at", "state", "created_at"),
)

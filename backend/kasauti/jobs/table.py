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
    String,
    Table,
    Text,
    false,
)

from kasauti.db.schema import Base
from kasauti.db.types import UtcDateTime

PAYLOAD_LIMIT = 64 * 1024
"""Bytes of JSON: enough for references and options, too small for a configuration."""
RESULT_LIMIT = 32 * 1024 * 1024
"""Bytes of JSON a job may return. An audit's result is about 550 bytes per configuration line
(a 6,100-line Cisco configuration gave 3.3 MB, measured 2026-09-27), so this holds about 60,000
lines; the limit bounds what a worker can make the server hold, not what an audit may be."""
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
    Column("result", Text, comment="canonical JSON object, once succeeded"),
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

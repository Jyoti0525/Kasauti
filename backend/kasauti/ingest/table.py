"""The ``uploads`` and ``upload_files`` tables (PLAN §5.1; TODO M2.04).

An upload is what the "New audit" screen builds (PLAN §18.1): files dropped one by one, as a
folder or as a ``.zip``, then started together. Each file the user sent is one row, accepted or
not, so the upload reports every file it was given, including the ones it refused and why
(R-04: "malformed files are reported").

Rows hold names, sizes, hashes and reasons, never configuration text. The text itself waits in
the staging area on disk (:mod:`kasauti.ingest.staging`) until its audit job reads it. What a
file was recognised as (TODO M2.06) is its sort job's result; a device chosen by hand is kept
here, and ``paired_with`` names another row of the same upload (the store keeps it so). So are
device details typed by hand (TODO M2.19), on the row of the file that is the device.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    String,
    Table,
    Text,
    false,
)

from kasauti.db.schema import Base
from kasauti.db.types import UtcDateTime

NAME_LIMIT = 512
"""Characters of a file's display name (its path inside a folder or archive)."""
LABEL_LIMIT = 200
REASON_LIMIT = 500


class UploadState(StrEnum):
    OPEN = "open"
    """Taking files."""
    STARTED = "started"
    """Its audit jobs are queued; no more files."""
    DISCARDED = "discarded"
    """The user threw it away before starting; its files are deleted."""
    EXPIRED = "expired"
    """Left open too long; its files are deleted."""


def _in(column: str, enum: type[StrEnum]) -> str:
    return f"{column} IN ({', '.join(repr(s.value) for s in enum)})"


uploads = Table(
    "uploads",
    Base.metadata,
    Column("id", String(36), primary_key=True, comment="UUID 4"),
    Column("label", String(LABEL_LIMIT), comment="the user's name for this audit"),
    Column("state", String(16), nullable=False),
    Column("frameworks", Text, nullable=False, comment="JSON list of framework ids"),
    Column("vendor", String(64), comment="vendor pack chosen by the user; null = fingerprint"),
    Column("created_at", UtcDateTime, nullable=False),
    Column("touched_at", UtcDateTime, nullable=False, comment="last change; open ones expire"),
    Column("started_at", UtcDateTime),
    CheckConstraint(_in("state", UploadState), name="state"),
)

upload_files = Table(
    "upload_files",
    Base.metadata,
    Column("id", String(36), primary_key=True, comment="UUID 4; also its staged file's name"),
    Column(
        "upload_id",
        String(36),
        ForeignKey("uploads.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("name", String(NAME_LIMIT), nullable=False, comment="display only; never a path"),
    Column("size", BigInteger, nullable=False, comment="bytes received (expanded, in a zip)"),
    Column("sha256", String(64), comment="of the bytes received; null if not all were read"),
    Column("accepted", Boolean, nullable=False),
    Column("reason", String(REASON_LIMIT), comment="why it was refused; never file content"),
    Column(
        "job_id",
        String(36),
        ForeignKey("jobs.id", ondelete="SET NULL"),
        comment="its audit, once the upload is started",
    ),
    Column("created_at", UtcDateTime, nullable=False),
    Column(
        "sort_job_id",
        String(36),
        ForeignKey("jobs.id", ondelete="SET NULL"),
        comment="the job recognising it: config or command output, vendor, hostname (M2.06)",
    ),
    Column(
        "manual",
        Boolean,
        nullable=False,
        server_default=false(),
        comment="its device was chosen by hand (M2.06)",
    ),
    Column(
        "paired_with",
        String(36),
        comment="with manual: the configuration it goes with; null = left out",
    ),
    Column(
        "entered",
        Text,
        comment="JSON: device details typed by hand for this device's audit (M2.19)",
    ),
    CheckConstraint("size >= 0", name="size"),
    CheckConstraint(
        "(accepted AND reason IS NULL) OR (NOT accepted AND reason IS NOT NULL)", name="reason"
    ),
    CheckConstraint("manual OR paired_with IS NULL", name="pairing"),
    Index("ix_upload_files_upload_id", "upload_id"),
)

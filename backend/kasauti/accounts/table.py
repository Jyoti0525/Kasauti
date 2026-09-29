"""The ``accounts`` and ``sessions`` tables (PLAN §17; TODO M5.03-M5.05).

One team, one workspace: every account sees the same fleet, and its role says what it may
change. Rows hold an Argon2id hash, never a password; a session row holds the SHA-256 of its
token, never the token, so a copy of the database signs no one in.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
)

from kasauti.db.schema import Base
from kasauti.db.types import UtcDateTime

USERNAME_LIMIT = 32
NAME_LIMIT = 80


class Role(StrEnum):
    """Least privilege first: each role may do what the ones before it may, and more."""

    VIEWER = "viewer"
    """Reads audits and reports."""
    AUDITOR = "auditor"
    """Also uploads configurations and runs audits."""
    TRAINER = "trainer"
    """Also teaches the Training Studio; a lesson that makes a check pass waits for an approver."""
    APPROVER = "approver"
    """Also approves another person's lesson that makes a check pass (four-eyes)."""
    ADMIN = "admin"
    """Everything, and manages accounts."""


RANK = {role: i for i, role in enumerate(Role)}

accounts = Table(
    "accounts",
    Base.metadata,
    Column("id", String(36), primary_key=True, comment="UUID 4"),
    Column("username", String(USERNAME_LIMIT), nullable=False, unique=True, comment="lower case"),
    Column("name", String(NAME_LIMIT), nullable=False, comment="as shown in the UI"),
    Column("password_hash", String(256), nullable=False, comment="Argon2id, PHC string"),
    Column("role", String(16), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("failed_logins", Integer, nullable=False, comment="since the last good one"),
    Column("locked_until", UtcDateTime, comment="too many wrong passwords: refused until then"),
    CheckConstraint(f"role IN ({', '.join(repr(r.value) for r in Role)})", name="role"),
)

sessions = Table(
    "sessions",
    Base.metadata,
    Column("id", String(64), primary_key=True, comment="SHA-256 of the cookie's token"),
    Column(
        "account_id",
        String(36),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("created_at", UtcDateTime, nullable=False),
    Column("seen_at", UtcDateTime, nullable=False, comment="last request; idle ones end"),
    Column("expires_at", UtcDateTime, nullable=False, comment="ends then, however active"),
    Index("ix_sessions_account_id", "account_id"),
)

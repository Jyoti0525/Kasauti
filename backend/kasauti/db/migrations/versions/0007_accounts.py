"""team accounts and sign-in sessions (TODO M5.03-M5.05)

Revision ID: 0007
Revises: 0006
Created: 2026-09-29 18:00:00

Two new tables, ``accounts`` (an Argon2id hash per person, and a role) and ``sessions`` (the
SHA-256 of each sign-in's token). Nothing existing changes: audits and uploads belong to the
team, and every account sees them.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Plain types only, as in 0002; the application reads timestamps through UtcDateTime.
    op.create_table(
        "accounts",
        sa.Column("id", sa.String(length=36), nullable=False, comment="UUID 4"),
        sa.Column("username", sa.String(length=32), nullable=False, comment="lower case"),
        sa.Column("name", sa.String(length=80), nullable=False, comment="as shown in the UI"),
        sa.Column(
            "password_hash", sa.String(length=256), nullable=False, comment="Argon2id, PHC string"
        ),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False, comment="since the last good one"),
        sa.Column(
            "locked_until",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="too many wrong passwords: refused until then",
        ),
        sa.CheckConstraint(
            "role IN ('viewer', 'auditor', 'trainer', 'approver', 'admin')",
            name=op.f("ck_accounts_role"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_accounts")),
        sa.UniqueConstraint("username", name=op.f("uq_accounts_username")),
    )
    op.create_table(
        "sessions",
        sa.Column(
            "id", sa.String(length=64), nullable=False, comment="SHA-256 of the cookie's token"
        ),
        sa.Column("account_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="last request; idle ones end",
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="ends then, however active",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["accounts.id"],
            name=op.f("fk_sessions_account_id_accounts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
    )
    op.create_index("ix_sessions_account_id", "sessions", ["account_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_sessions_account_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("accounts")

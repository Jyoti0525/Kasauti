"""job queue (TODO M2.03)

Revision ID: 0002
Revises: 0001
Created: 2026-09-26 23:54:50.492662
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Plain types only: a migration must not change when application code does. The
    # application reads these timestamps through kasauti.db.types.UtcDateTime.
    op.create_table(
        "jobs",
        sa.Column(
            "id",
            sa.String(length=36),
            nullable=False,
            comment="UUID 4; not guessable, not a counter",
        ),
        sa.Column(
            "kind",
            sa.String(length=64),
            nullable=False,
            comment="a key of kasauti.jobs.kinds.HANDLERS",
        ),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False, comment="canonical JSON object"),
        sa.Column(
            "result", sa.Text(), nullable=True, comment="canonical JSON object, once succeeded"
        ),
        sa.Column(
            "error",
            sa.String(length=500),
            nullable=True,
            comment="why it failed; never configuration text",
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, comment="times claimed by a worker"),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column(
            "timeout_s", sa.Integer(), nullable=False, comment="wall-clock limit per attempt"
        ),
        sa.Column("cancel_requested", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column(
            "worker",
            sa.String(length=128),
            nullable=True,
            comment="the pool holding it while running",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="the holding pool renews it; stale means lost",
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_jobs_state"),
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND attempts <= max_attempts", name=op.f("ck_jobs_attempts")
        ),
        sa.CheckConstraint("max_attempts >= 1", name=op.f("ck_jobs_max_attempts")),
        sa.CheckConstraint("timeout_s >= 1", name=op.f("ck_jobs_timeout_s")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
    )
    op.create_index("ix_jobs_state_created_at", "jobs", ["state", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_jobs_state_created_at", table_name="jobs")
    op.drop_table("jobs")

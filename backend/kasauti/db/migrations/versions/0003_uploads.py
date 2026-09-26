"""uploads (TODO M2.04)

Revision ID: 0003
Revises: 0002
Created: 2026-09-27 02:13:31.245119
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Plain types only, as in 0002; the application reads timestamps through UtcDateTime.
    op.create_table(
        "uploads",
        sa.Column("id", sa.String(length=36), nullable=False, comment="UUID 4"),
        sa.Column(
            "label", sa.String(length=200), nullable=True, comment="the user's name for this audit"
        ),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("frameworks", sa.Text(), nullable=False, comment="JSON list of framework ids"),
        sa.Column(
            "vendor",
            sa.String(length=64),
            nullable=True,
            comment="vendor pack chosen by the user; null = fingerprint",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "touched_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="last change; open ones expire",
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('open', 'started', 'discarded', 'expired')", name=op.f("ck_uploads_state")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_uploads")),
    )
    op.create_table(
        "upload_files",
        sa.Column(
            "id",
            sa.String(length=36),
            nullable=False,
            comment="UUID 4; also its staged file's name",
        ),
        sa.Column("upload_id", sa.String(length=36), nullable=False),
        sa.Column(
            "name", sa.String(length=512), nullable=False, comment="display only; never a path"
        ),
        sa.Column(
            "size", sa.BigInteger(), nullable=False, comment="bytes received (expanded, in a zip)"
        ),
        sa.Column(
            "sha256",
            sa.String(length=64),
            nullable=True,
            comment="of the bytes received; null if not all were read",
        ),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column(
            "reason",
            sa.String(length=500),
            nullable=True,
            comment="why it was refused; never file content",
        ),
        sa.Column(
            "job_id",
            sa.String(length=36),
            nullable=True,
            comment="its audit, once the upload is started",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(accepted AND reason IS NULL) OR (NOT accepted AND reason IS NOT NULL)",
            name=op.f("ck_upload_files_reason"),
        ),
        sa.CheckConstraint("size >= 0", name=op.f("ck_upload_files_size")),
        sa.ForeignKeyConstraint(
            ["job_id"], ["jobs.id"], name=op.f("fk_upload_files_job_id_jobs"), ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["upload_id"],
            ["uploads.id"],
            name=op.f("fk_upload_files_upload_id_uploads"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_upload_files")),
    )
    op.create_index("ix_upload_files_upload_id", "upload_files", ["upload_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_upload_files_upload_id", table_name="upload_files")
    op.drop_table("upload_files")
    op.drop_table("uploads")

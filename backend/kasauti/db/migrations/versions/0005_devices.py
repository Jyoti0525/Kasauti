"""files grouped into devices (TODO M2.06)

Revision ID: 0005
Revises: 0004
Created: 2026-09-27 18:00:00

``upload_files`` gains ``sort_job_id`` (the job that recognises the file: configuration or
command output, vendor, hostname), and ``manual`` and ``paired_with`` (a device chosen by
hand). Existing rows get no sort job and no manual choice: an upload that is still open is
recognised when its next file arrives or when it is started, and started ones are finished.

On SQLite the table is rebuilt in batch mode (copy and swap). Nothing refers to
``upload_files``, so the rebuild can't null another table's references (0004's concern).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("upload_files") as batch:
        batch.add_column(
            sa.Column(
                "sort_job_id",
                sa.String(length=36),
                nullable=True,
                comment="the job recognising it: config or command output, vendor, hostname "
                "(M2.06)",
            )
        )
        batch.add_column(
            sa.Column(
                "manual",
                sa.Boolean(),
                server_default=sa.false(),
                nullable=False,
                comment="its device was chosen by hand (M2.06)",
            )
        )
        batch.add_column(
            sa.Column(
                "paired_with",
                sa.String(length=36),
                nullable=True,
                comment="with manual: the configuration it goes with; null = left out",
            )
        )
        batch.create_foreign_key(
            op.f("fk_upload_files_sort_job_id_jobs"),
            "jobs",
            ["sort_job_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_check_constraint(
            op.f("ck_upload_files_pairing"), "manual OR paired_with IS NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("upload_files") as batch:
        batch.drop_constraint(op.f("ck_upload_files_pairing"), type_="check")
        batch.drop_constraint(op.f("fk_upload_files_sort_job_id_jobs"), type_="foreignkey")
        batch.drop_column("paired_with")
        batch.drop_column("manual")
        batch.drop_column("sort_job_id")

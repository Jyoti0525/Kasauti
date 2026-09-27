"""device details entered by hand (TODO M2.19)

Revision ID: 0006
Revises: 0005
Created: 2026-09-27 23:00:00

``upload_files`` gains ``entered``: device details (serial, model…) typed by hand for the
device a file is, as JSON, passed to its audit. Existing rows get none.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("upload_files") as batch:
        batch.add_column(
            sa.Column(
                "entered",
                sa.Text(),
                nullable=True,
                comment="JSON: device details typed by hand for this device's audit (M2.19)",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("upload_files") as batch:
        batch.drop_column("entered")

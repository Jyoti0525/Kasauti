"""job results stored gzip-compressed (TODO M2.04 follow-up)

Revision ID: 0004
Revises: 0003
Created: 2026-09-27 03:10:00

``jobs.result`` (canonical JSON text) becomes ``jobs.result_gzip`` (the same text, gzipped:
kasauti.jobs.results). Results already stored are converted in place, online. The column is
dropped with a plain ``ALTER TABLE ... DROP COLUMN`` (SQLite 3.35+, PostgreSQL), never a batch
copy-and-swap: on SQLite that would drop and recreate ``jobs``, and with foreign keys on, the
drop would null every ``upload_files.job_id``.

Offline (``--sql``) the conversion can't be written as SQL: the script changes the schema only,
so results of already-finished jobs are not carried over. Re-run those audits, or upgrade online.
"""

from __future__ import annotations

import zlib
from collections.abc import Callable, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import context, op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BATCH = 100


def _gzip(text: str) -> bytes:
    packer = zlib.compressobj(6, zlib.DEFLATED, 31)
    return packer.compress(text.encode()) + packer.flush()


def _gunzip(blob: bytes) -> str:
    return zlib.decompress(blob, 31).decode()


def _convert(source: str, target: str, change: Callable[[Any], object]) -> None:
    """Copy every job's ``source`` into ``target`` through ``change``, a batch at a time."""
    if context.is_offline_mode():
        op.execute(f"-- {source} values are not converted to {target} by offline SQL")
        return
    conn = op.get_bind()
    jobs = sa.table("jobs", sa.column("id"), sa.column(source), sa.column(target))
    after = ""
    while True:
        rows = conn.execute(
            sa.select(jobs.c.id, jobs.c[source])
            .where(jobs.c[source].is_not(None), jobs.c.id > after)
            .order_by(jobs.c.id)
            .limit(_BATCH)
        ).all()
        if not rows:
            return
        for job_id, value in rows:
            conn.execute(sa.update(jobs).where(jobs.c.id == job_id).values({target: change(value)}))
        after = rows[-1][0]


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column(
            "result_gzip",
            sa.LargeBinary(),
            nullable=True,
            comment="gzip of the canonical JSON object, once succeeded (kasauti.jobs.results)",
        ),
    )
    _convert("result", "result_gzip", _gzip)
    op.execute("ALTER TABLE jobs DROP COLUMN result")


def downgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column(
            "result", sa.Text(), nullable=True, comment="canonical JSON object, once succeeded"
        ),
    )
    _convert("result_gzip", "result", _gunzip)
    op.execute("ALTER TABLE jobs DROP COLUMN result_gzip")

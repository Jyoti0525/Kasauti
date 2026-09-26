"""Baseline: an empty Kasauti schema.

Marks a database as Kasauti's (Alembic records the revision in ``alembic_version``). Tables
arrive with the milestones that need them, each in its own revision after this one.

Revision ID: 0001
Revises:
Created: 2026-09-26
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

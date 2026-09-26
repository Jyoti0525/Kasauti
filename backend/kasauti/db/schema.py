"""The ORM base every table derives from.

Tables arrive with the milestones that need them (jobs M2.03, uploads M2.04), each with its own
Alembic migration. ``tests/db`` fails if a table here and the migrations ever disagree.

Constraint names follow one convention, so a migration can name the constraint it changes;
SQLite's batch mode (a table rebuilt to alter it) depends on it.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

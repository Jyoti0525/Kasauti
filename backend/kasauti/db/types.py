"""Column types shared by every table."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator[dt.datetime]):
    """A moment in UTC, the same on SQLite and PostgreSQL.

    Naive datetimes are refused rather than guessed at. SQLite keeps no time zone, so values are
    stored there as naive UTC in SQLAlchemy's fixed-width format, which also makes ``<`` in SQL
    compare them correctly; PostgreSQL stores ``timestamptz``. Either way they come back aware.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect: Dialect) -> Any:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime; pass one with a time zone (UTC)")
        value = value.astimezone(dt.UTC)
        return value.replace(tzinfo=None) if dialect.name == "sqlite" else value

    def process_result_value(self, value: Any, dialect: Dialect) -> dt.datetime | None:
        if value is None:
            return None
        if not isinstance(value, dt.datetime):  # the driver broke the impl type's promise
            raise TypeError(f"expected a datetime from the database, got {type(value).__name__}")
        return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value.astimezone(dt.UTC)

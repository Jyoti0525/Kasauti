"""Persistence (PLAN §4.2 "Storage", §19.1; TODO M2.02).

SQLite in WAL mode by default: zero setup, one file, easy to back up on an air-gapped site.
PostgreSQL through psycopg 3 for multi-user servers (``uv sync --extra postgresql``). The schema
is owned by Alembic migrations; the pipeline core never touches the database.
"""

from kasauti.db.engine import (
    DATABASE_URL_ENV,
    DatabaseConfigError,
    create_engine,
    database_url,
    exists,
    redacted,
)
from kasauti.db.migrate import SchemaError, current_revision, ensure_current, head_revision, upgrade

__all__ = [
    "DATABASE_URL_ENV",
    "DatabaseConfigError",
    "SchemaError",
    "create_engine",
    "current_revision",
    "database_url",
    "ensure_current",
    "exists",
    "head_revision",
    "redacted",
    "upgrade",
]

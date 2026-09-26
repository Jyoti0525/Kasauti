"""Schema migrations (Alembic), run from code: ``kasauti db upgrade`` and ``kasauti serve``.

The migration scripts live in the package (``kasauti/db/migrations``), so an installed Kasauti
carries them. Developers add one with ``uv run alembic revision --autogenerate --rev-id NNNN -m
"..."`` from the repository root (``alembic.ini`` there points at the same scripts).
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


class SchemaError(RuntimeError):
    """The database's schema isn't the one this version of Kasauti expects."""


def config(engine: Engine | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.attributes["engine"] = engine
    return cfg


def head_revision() -> str:
    head = ScriptDirectory.from_config(config()).get_current_head()
    if head is None:  # pragma: no cover - the package always carries the baseline
        raise SchemaError("no migrations found")
    return head


def current_revision(engine: Engine) -> str | None:
    """The revision the database is at; ``None`` for a database never migrated."""
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def upgrade(engine: Engine, revision: str = "head") -> None:
    command.upgrade(config(engine), revision)


def downgrade(engine: Engine, revision: str) -> None:
    command.downgrade(config(engine), revision)


def ensure_current(engine: Engine) -> str:
    """The database's revision if it is the head; :class:`SchemaError` otherwise."""
    current, head = current_revision(engine), head_revision()
    if current != head:
        state = "has no Kasauti schema" if current is None else f"is at schema {current}"
        raise SchemaError(
            f"the database {state}; this version needs {head}. Run `kasauti db upgrade`."
        )
    return current

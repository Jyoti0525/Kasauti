"""Alembic environment for Kasauti's schema.

Online: the engine comes from :func:`kasauti.db.migrate.config` (``kasauti db upgrade``) or, run
through the ``alembic`` command by a developer, from ``KASAUTI_DATABASE_URL`` or ``./var``,
with the same connection setup the application uses. Each migration runs in its own
transaction; SQLite alters tables in batch mode (copy and swap), since its ``ALTER TABLE`` is
limited.

Offline (``--sql``): the SQL a DBA can review before applying it, for the URL in the config or
else the one the application would use. Nothing is connected to or created.
"""

from __future__ import annotations

from pathlib import Path

from alembic import context
from sqlalchemy import Engine, make_url

from kasauti.db.engine import create_engine, database_url
from kasauti.db.schema import Base

config = context.config
target_metadata = Base.metadata


def run_offline() -> None:
    given = config.get_main_option("sqlalchemy.url")
    url = make_url(given) if given else database_url(Path("var"))
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=url.get_backend_name() == "sqlite",
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    engine: Engine | None = config.attributes.get("engine")
    owned = engine is None
    if engine is None:
        engine = create_engine(database_url(Path("var")))
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=connection.dialect.name == "sqlite",
                transaction_per_migration=True,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        if owned:
            engine.dispose()


if context.is_offline_mode():
    run_offline()
else:
    run_online()

"""The migration chain and the ORM agree, and upgrade on every supported database (M2.02)."""

from __future__ import annotations

import io
import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, make_url

from kasauti.db import (
    SchemaError,
    create_engine,
    current_revision,
    database_url,
    ensure_current,
    head_revision,
    upgrade,
)
from kasauti.db.migrate import MIGRATIONS, config, downgrade
from kasauti.db.tables import metadata

LIVE_POSTGRES = "KASAUTI_TEST_POSTGRES_URL"


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    eng = create_engine(database_url(tmp_path, environ={}))
    yield eng
    eng.dispose()


def test_one_linear_chain_of_numbered_revisions() -> None:
    scripts = ScriptDirectory.from_config(config())
    assert scripts.get_heads() == [head_revision()]
    revisions = list(scripts.walk_revisions())
    for rev in revisions:
        assert rev.path is not None
        # Files are NNNN_slug.py and carry their own number, so the order is readable.
        assert re.fullmatch(rf"{rev.revision}_[a-z0-9_]+\.py", Path(rev.path).name), rev.path
        assert re.fullmatch(r"\d{4}", rev.revision)
    numbers = sorted(int(r.revision) for r in revisions)
    assert numbers == list(range(1, len(numbers) + 1))


def test_a_new_database_is_upgraded_to_the_head(engine: Engine) -> None:
    assert current_revision(engine) is None
    with pytest.raises(SchemaError, match="has no Kasauti schema"):
        ensure_current(engine)
    upgrade(engine)
    assert ensure_current(engine) == head_revision()
    upgrade(engine)  # idempotent
    assert current_revision(engine) == head_revision()


def test_the_migrations_build_exactly_the_tables_the_code_declares(engine: Engine) -> None:
    upgrade(engine)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), metadata)
    assert diff == [], "the ORM and the migrations disagree; add a migration"


def test_every_migration_can_be_undone_and_redone(engine: Engine) -> None:
    upgrade(engine)
    downgrade(engine, "base")
    assert current_revision(engine) is None
    upgrade(engine)
    assert current_revision(engine) == head_revision()


def test_an_old_schema_names_the_fix(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    upgrade(engine)
    at = head_revision()
    monkeypatch.setattr("kasauti.db.migrate.head_revision", lambda: "9999")
    with pytest.raises(SchemaError, match=rf"is at schema {at}; this version needs 9999.*upgrade"):
        ensure_current(engine)


def test_the_postgresql_sql_renders_for_review_without_a_server() -> None:
    """``alembic upgrade --sql``: what a DBA reviews before applying it on a shared server."""
    buffer = io.StringIO()
    cfg = config()
    cfg.output_buffer = buffer
    cfg.set_main_option("sqlalchemy.url", "postgresql+psycopg://kasauti@localhost/kasauti")
    command.upgrade(cfg, "head", sql=True)
    sql = buffer.getvalue()
    assert "CREATE TABLE alembic_version" in sql
    assert "CREATE TABLE jobs" in sql
    assert "cancel_requested BOOLEAN DEFAULT false NOT NULL" in sql  # not 0: PostgreSQL refuses
    # The first revision is inserted, each later one updates it; the last one written wins.
    stamps = re.findall(
        r"alembic_version (?:\(version_num\) VALUES \(|SET version_num=)'(\d+)'", sql
    )
    assert stamps
    assert stamps[-1] == head_revision()


def test_the_migrations_ship_inside_the_package() -> None:
    assert MIGRATIONS.is_relative_to(Path(__file__).resolve().parents[2] / "kasauti")
    assert (MIGRATIONS / "script.py.mako").is_file()


@pytest.mark.skipif(LIVE_POSTGRES not in os.environ, reason=f"set {LIVE_POSTGRES} to run")
def test_a_live_postgresql_server_upgrades_and_round_trips() -> None:
    engine = create_engine(make_url(os.environ[LIVE_POSTGRES]))
    try:
        upgrade(engine)
        assert ensure_current(engine) == head_revision()
        with engine.connect() as conn:
            assert compare_metadata(MigrationContext.configure(conn), metadata) == []
        downgrade(engine, "base")
        upgrade(engine)
        assert current_revision(engine) == head_revision()
    finally:
        engine.dispose()

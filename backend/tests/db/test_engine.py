"""Which databases are accepted, and how every SQLite connection is set up (TODO M2.02)."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import URL, Engine, inspect, make_url, text

from kasauti.db import DATABASE_URL_ENV, DatabaseConfigError, create_engine, database_url, redacted
from kasauti.db.engine import exists, validate


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    eng = create_engine(database_url(tmp_path, environ={}))
    yield eng
    eng.dispose()  # Windows can't delete an open file


def test_default_is_a_sqlite_file_in_the_data_directory(tmp_path: Path) -> None:
    url = database_url(tmp_path / "var", environ={})
    assert url.drivername == "sqlite+pysqlite"
    assert Path(str(url.database)) == (tmp_path / "var" / "kasauti.db").resolve()


@pytest.mark.parametrize(
    ("given", "driver"),
    [
        ("sqlite:///k.db", "sqlite+pysqlite"),
        ("postgresql://kasauti@localhost/kasauti", "postgresql+psycopg"),
        ("postgresql+psycopg://kasauti@127.0.0.1/kasauti", "postgresql+psycopg"),
    ],
)
def test_the_environment_names_the_database_and_the_driver_is_made_explicit(
    given: str, driver: str
) -> None:
    assert database_url(Path("var"), environ={DATABASE_URL_ENV: given}).drivername == driver


@pytest.mark.parametrize(
    ("given", "problem"),
    [
        ("mysql://u:p@h/d", "unsupported database 'mysql'"),
        # psycopg2 is another driver (and licence); only psycopg 3 is accepted.
        ("postgresql+psycopg2://u@localhost/d", "unsupported database"),
        ("sqlite://", "needs a file path"),
        ("sqlite:///:memory:", "needs a file path"),
        ("sqlite:///file:k.db?mode=memory&uri=true", "needs a file path"),
        ("sqlite:///k.db?timeout=0", "options aren't accepted"),
    ],
)
def test_other_databases_and_throwaway_ones_are_refused(given: str, problem: str) -> None:
    with pytest.raises(DatabaseConfigError, match=problem):
        database_url(Path("var"), environ={DATABASE_URL_ENV: given})


def test_a_malformed_url_is_refused_without_echoing_it() -> None:
    with pytest.raises(DatabaseConfigError) as err:
        database_url(Path("var"), environ={DATABASE_URL_ENV: "not a url hunter2"})
    assert "hunter2" not in str(err.value)


@pytest.mark.parametrize(
    ("given", "accepted"),
    [
        ("postgresql://k:pw@db.example.org/k", False),
        ("postgresql://k:pw@db.example.org/k?sslmode=require", False),  # encrypted, unverified
        ("postgresql://k:pw@db.example.org/k?sslmode=prefer", False),
        ("postgresql://k:pw@db.example.org/k?sslmode=verify-ca", True),
        ("postgresql://k:pw@db.example.org/k?sslmode=verify-full", True),
        ("postgresql://k:pw@localhost/k", True),
        ("postgresql://k:pw@[::1]/k", True),
        ("postgresql://k@/k", True),  # the default Unix socket
        ("postgresql://k@/k?host=/var/run/postgresql", True),
        ("postgresql://k@/k?host=db.example.org", False),  # a host given as an option
    ],
)
def test_a_server_elsewhere_must_be_reached_over_verified_tls(given: str, accepted: bool) -> None:
    if accepted:
        assert validate(make_url(given)).drivername == "postgresql+psycopg"
    else:
        with pytest.raises(DatabaseConfigError, match="sslmode=verify-full") as err:
            validate(make_url(given))
        assert "pw" not in str(err.value).replace("PostgreSQL", "")


def test_messages_name_the_database_but_never_the_password(tmp_path: Path) -> None:
    pg = make_url("postgresql+psycopg://kasauti:hunter2@localhost/kasauti")
    assert redacted(pg) == "postgresql+psycopg://kasauti:***@localhost/kasauti"
    sqlite = database_url(tmp_path, environ={})
    assert redacted(sqlite) == f"SQLite {sqlite.database}"


def test_the_file_is_created_on_first_use_only(tmp_path: Path) -> None:
    url = database_url(tmp_path / "var", environ={})
    assert not exists(url)
    create_engine(url).dispose()
    assert exists(url)
    assert exists(make_url("postgresql+psycopg://k@localhost/k"))  # can't know; not refused


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes; Windows relies on the profile's ACLs")
def test_the_file_and_directory_are_private_to_this_user(tmp_path: Path) -> None:
    url = database_url(tmp_path / "var", environ={})
    create_engine(url).dispose()
    assert (tmp_path / "var").stat().st_mode & 0o777 == 0o700
    assert Path(str(url.database)).stat().st_mode & 0o777 == 0o600


def test_every_connection_gets_the_hardened_pragmas(engine: Engine) -> None:
    expected = {
        "journal_mode": "wal",
        "foreign_keys": 1,
        "busy_timeout": 5000,
        "synchronous": 2,  # FULL
        "secure_delete": 1,
        "trusted_schema": 0,
    }
    for _ in range(2):  # a pooled connection and a fresh one
        with engine.connect() as conn:
            got = {name: conn.exec_driver_sql(f"PRAGMA {name}").scalar() for name in expected}
        assert got == expected
        engine.dispose()


def test_ddl_is_transactional(engine: Engine) -> None:
    with engine.connect() as conn:
        conn.execute(text("CREATE TABLE t (x INTEGER)"))
        conn.rollback()
    assert not inspect(engine).has_table("t")


def test_foreign_keys_are_enforced(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE p (id INTEGER PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE c (p INTEGER REFERENCES p(id))"))
    with pytest.raises(Exception, match="FOREIGN KEY"), engine.begin() as conn:
        conn.execute(text("INSERT INTO c VALUES (1)"))


def test_a_transaction_takes_the_write_lock_when_it_starts(engine: Engine) -> None:
    """``BEGIN IMMEDIATE``: another writer waits (or, with no timeout, fails) from the start,
    so two processes never deadlock trying to upgrade read locks to write locks."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))  # a read, but the transaction already holds the lock
        other = sqlite3.connect(str(engine.url.database), timeout=0, isolation_level=None)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
        finally:
            other.close()


def test_the_engine_refuses_what_validate_refuses() -> None:
    with pytest.raises(DatabaseConfigError):
        create_engine(URL.create("sqlite+pysqlite", database=":memory:"))


def test_failed_statements_do_not_echo_their_parameters(engine: Engine) -> None:
    with pytest.raises(Exception, match="no such table") as err, engine.connect() as conn:
        conn.execute(text("INSERT INTO missing VALUES (:v)"), {"v": "enable secret 5 $1$abc"})
    assert "$1$abc" not in str(err.value)

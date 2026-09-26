"""Which database, and how every connection to it is set up.

The URL comes from ``KASAUTI_DATABASE_URL`` or, when that isn't set, is a SQLite file in the data
directory. Never from a command-line argument: a PostgreSQL URL carries a password, and argv is
readable by every user on the machine.

Only two drivers are accepted, the two PLAN §19.1 names: the standard library's ``sqlite3`` and
psycopg 3. Anything else is refused rather than loaded.

SQLite connections (every one, on connect):

* ``journal_mode=WAL``: readers never block the writer, and the file survives a crash. Checked,
  because SQLite silently keeps the old mode where WAL can't work (some network filesystems).
* ``foreign_keys=ON``: off by default in SQLite, per connection.
* ``busy_timeout=5000``: wait for another process's write instead of failing at once.
* ``synchronous=FULL``: an acknowledged write survives power loss. Audit history is evidence.
* ``secure_delete=ON``: deleted rows are overwritten, so retention deletes really delete.
* ``trusted_schema=OFF``: SQL functions in the schema can't run with side effects (SQLite's
  own hardening advice for files that could be tampered with).
* Transactions start with ``BEGIN IMMEDIATE`` (the driver's own transaction handling is off, as
  SQLAlchemy documents): a transaction takes the write lock when it starts, so two processes
  never deadlock upgrading read locks, and DDL in migrations is transactional.

PostgreSQL: a server that isn't on this machine must be reached with ``sslmode=verify-full`` or
``verify-ca``; configurations would otherwise cross the network in the clear, or to an
impostor.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

import sqlalchemy
from sqlalchemy import URL, Engine, event, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.pool import ConnectionPoolEntry

DATABASE_URL_ENV = "KASAUTI_DATABASE_URL"
SQLITE_FILE = "kasauti.db"
SQLITE = "sqlite+pysqlite"
POSTGRESQL = "postgresql+psycopg"
DRIVERS = {"sqlite": SQLITE, SQLITE: SQLITE, "postgresql": POSTGRESQL, POSTGRESQL: POSTGRESQL}
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
VERIFIED_TLS = frozenset({"verify-full", "verify-ca"})
SQLITE_PRAGMAS = (
    ("foreign_keys", "ON"),
    ("busy_timeout", "5000"),
    ("synchronous", "FULL"),
    ("secure_delete", "ON"),
    ("trusted_schema", "OFF"),
)


class DatabaseConfigError(ValueError):
    """The configured database can't be used as given. The message never contains a password."""


def database_url(data_dir: Path, environ: dict[str, str] | None = None) -> URL:
    """The database to use: ``KASAUTI_DATABASE_URL`` if set, else ``<data_dir>/kasauti.db``."""
    env = os.environ if environ is None else environ
    given = env.get(DATABASE_URL_ENV, "").strip()
    if not given:
        return URL.create(SQLITE, database=str(data_dir.resolve() / SQLITE_FILE))
    try:
        url = make_url(given)
    except ArgumentError:
        # The text may hold a password: say where it came from, not what it was.
        raise DatabaseConfigError(f"{DATABASE_URL_ENV} is not a database URL") from None
    return validate(url)


def validate(url: URL) -> URL:
    """``url`` with its driver made explicit, or :class:`DatabaseConfigError`."""
    driver = DRIVERS.get(url.drivername)
    if driver is None:
        raise DatabaseConfigError(
            f"unsupported database {url.drivername!r}: use sqlite or postgresql (psycopg 3)"
        )
    url = url.set(drivername=driver)
    if driver == SQLITE:
        if not url.database or url.database == ":memory:" or url.database.startswith("file:"):
            raise DatabaseConfigError("SQLite needs a file path; an in-memory database is lost")
        if url.query:
            raise DatabaseConfigError("SQLite URL options aren't accepted; Kasauti sets them")
        return url
    if not _local(url) and _query(url, "sslmode") not in VERIFIED_TLS:
        raise DatabaseConfigError(
            f"PostgreSQL on {url.host} must use sslmode=verify-full (or verify-ca): "
            "configurations would otherwise cross the network unverified"
        )
    return url


def redacted(url: URL) -> str:
    """The database for messages and logs: a SQLite file by its path, anything else by its URL
    with the password hidden."""
    if url.drivername == SQLITE and url.database:
        return f"SQLite {url.database}"
    return url.render_as_string(hide_password=True)


def exists(url: URL) -> bool:
    """False only for a SQLite file not created yet (a server database can't be checked
    without connecting)."""
    return url.drivername != SQLITE or Path(str(url.database)).is_file()


def create_engine(url: URL) -> Engine:
    """An engine for ``url`` (validated again here), set up as the module docstring says."""
    url = validate(url)
    # hide_parameters: a failed statement's error must not echo configuration text into logs.
    if url.drivername == SQLITE:
        _prepare_sqlite_file(Path(str(url.database)))
        engine = sqlalchemy.create_engine(
            url,
            hide_parameters=True,
            # The pool hands a connection to one thread at a time; FastAPI runs sync routes in
            # a thread pool, so the connection may not be used by the thread that opened it.
            connect_args={"check_same_thread": False},
        )
        event.listen(engine, "connect", _sqlite_connect)
        event.listen(engine, "begin", _sqlite_begin)
        return engine
    return sqlalchemy.create_engine(
        url,
        hide_parameters=True,
        pool_pre_ping=True,
        connect_args={"application_name": "kasauti", "connect_timeout": 10},
    )


def _local(url: URL) -> bool:
    host = url.host or _query(url, "host")
    # No host means the default Unix socket; a path is an explicit socket directory.
    return not host or host.startswith("/") or host in LOCAL_HOSTS


def _query(url: URL, key: str) -> str | None:
    value = url.query.get(key)
    return value[-1] if isinstance(value, tuple) else value


def _prepare_sqlite_file(path: Path) -> None:
    """Create the directory and file readable by this user only (POSIX modes; on Windows the
    user profile's ACLs apply). SQLite gives the -wal and -shm files the database's mode."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))


def _sqlite_connect(dbapi_connection: sqlite3.Connection, _record: ConnectionPoolEntry) -> None:
    # Hand transaction control to SQLAlchemy (see _sqlite_begin).
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    try:
        (mode,) = cursor.execute("PRAGMA journal_mode=WAL").fetchone()
        if str(mode).lower() != "wal":
            raise DatabaseConfigError(
                f"SQLite refused WAL mode (it kept {mode!r}); is the data directory on a "
                "network filesystem?"
            )
        for name, value in SQLITE_PRAGMAS:
            cursor.execute(f"PRAGMA {name}={value}")
    finally:
        cursor.close()


def _sqlite_begin(connection: Any) -> None:
    connection.exec_driver_sql("BEGIN IMMEDIATE")

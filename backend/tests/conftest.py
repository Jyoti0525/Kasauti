"""Fixtures shared across the backend tests."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, make_url

from kasauti.db import create_engine, database_url, upgrade
from kasauti.ingest.table import upload_files, uploads
from kasauti.jobs.table import jobs

LIVE_POSTGRES = "KASAUTI_TEST_POSTGRES_URL"


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgresql",
            marks=pytest.mark.skipif(
                LIVE_POSTGRES not in os.environ, reason=f"set {LIVE_POSTGRES} to run"
            ),
        ),
    ]
)
def any_engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    """A migrated, empty database of each kind Kasauti supports."""
    if request.param == "sqlite":
        engine = create_engine(database_url(tmp_path, environ={}))
    else:
        engine = create_engine(make_url(os.environ[LIVE_POSTGRES]))
    upgrade(engine)
    with engine.begin() as conn:
        for table in (upload_files, uploads, jobs):
            conn.execute(delete(table))
    yield engine
    engine.dispose()

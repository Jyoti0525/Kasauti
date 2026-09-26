from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, make_url

from kasauti.db import create_engine, database_url, upgrade
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
    """A migrated database of each kind Kasauti supports."""
    if request.param == "sqlite":
        engine = create_engine(database_url(tmp_path, environ={}))
    else:
        engine = create_engine(make_url(os.environ[LIVE_POSTGRES]))
    upgrade(engine)
    with engine.begin() as conn:
        conn.execute(delete(jobs))
    yield engine
    engine.dispose()


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    """A migrated SQLite database."""
    eng = create_engine(database_url(tmp_path, environ={}))
    upgrade(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def handlers(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    # Worker processes start with the parent's sys.path, so this reaches them too.
    monkeypatch.syspath_prepend(str(Path(__file__).parent))
    from job_handlers import HANDLERS  # noqa: PLC0415

    return dict(HANDLERS)

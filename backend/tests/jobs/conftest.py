from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine

from kasauti.db import create_engine, database_url, upgrade


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

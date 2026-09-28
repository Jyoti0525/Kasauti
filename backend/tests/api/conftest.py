"""Fixtures shared by the API tests: a migrated SQLite database per test, and an app on it."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kasauti.api.app import Settings, create_app
from kasauti.audit import KnowledgeBase, load_kb
from kasauti.db import create_engine, database_url, upgrade

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"
BASE = "http://127.0.0.1:8000"


@pytest.fixture(scope="module")
def migrated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One migrated database file, copied for each test (migrating each time costs ~0.5 s)."""
    folder = tmp_path_factory.mktemp("template")
    engine = create_engine(database_url(folder, environ={}))
    upgrade(engine)
    engine.dispose()
    return folder / "kasauti.db"


@pytest.fixture
def var(tmp_path: Path, migrated: Path) -> Path:
    shutil.copyfile(migrated, tmp_path / "kasauti.db")
    return tmp_path


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(PACKS)


@pytest.fixture
def client(var: Path, kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr("kasauti.api.app.load_kb", lambda _packs: kb)  # loading takes ~0.5 s
    app = create_app(
        Settings(packs=PACKS, database=database_url(var, environ={}), staging=var / "staging")
    )
    with TestClient(app, base_url=BASE) as test_client:
        yield test_client

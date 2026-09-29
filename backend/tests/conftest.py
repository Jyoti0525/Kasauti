"""Fixtures shared across the backend tests."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, make_url

from kasauti.accounts import DEMO_ACCOUNTS
from kasauti.accounts.table import accounts, sessions
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
        for table in (sessions, accounts, upload_files, uploads, jobs):
            conn.execute(delete(table))
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def cheap_password_hashes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Argon2id at its real cost (64 MiB, 3 passes) takes a tenth of a second a hash, and the
    tests sign in hundreds of times; the cost is the only thing this changes."""
    monkeypatch.setattr(
        "kasauti.accounts.store.HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


SignIn = Callable[..., dict[str, Any]]


@pytest.fixture
def sign_in() -> SignIn:
    """Sign a test client in as one of the demo accounts (the app needs ``demo_accounts``)."""

    def go(client: TestClient, username: str = "asha") -> dict[str, Any]:
        password = next(p for u, _, _, p in DEMO_ACCOUNTS if u == username)
        response = client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"X-Kasauti-Request": "1"},
        )
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    return go

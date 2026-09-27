"""R-04's acceptance test (TODO M2.09): 100 mixed files, a zip among them, all ingested;
malformed ones reported; nothing crashes; inside PLAN §22's three minutes."""

from __future__ import annotations

import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kasauti.api.app import Settings, create_app
from kasauti.db import create_engine, database_url, upgrade
from kasauti.jobs import WorkerPool, default_workers
from kasauti.jobs.kinds import HANDLERS

sys.path.insert(0, str(Path(__file__).parent))
from bulk import Row, corpus, zipped_bytes

REPO = Path(__file__).resolve().parents[3]
GUARD = {"X-Kasauti-Request": "1"}
BUDGET_S = 180.0


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    engine = create_engine(database_url(tmp_path, environ={}))
    upgrade(engine)
    engine.dispose()
    app = create_app(
        Settings(
            packs=REPO / "packs",
            database=database_url(tmp_path, environ={}),
            staging=tmp_path / "staging",
        )
    )
    with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
        yield test_client


def _send(client: TestClient, upload_id: str, name: str, data: bytes) -> None:
    response = client.post(
        f"/api/uploads/{upload_id}/files",
        content=data,
        headers={**GUARD, "Content-Type": "application/octet-stream", "X-File-Name": name},
    )
    assert response.status_code == 201, response.text


def test_a_hundred_mixed_files_are_all_accounted_for_within_budget(client: TestClient) -> None:
    direct, zipped = corpus()
    expected: dict[str, Row] = {r.name: r for r in (*direct, *zipped)}
    assert len(expected) == 100
    started = time.monotonic()
    upload_id = client.post("/api/uploads", json={"label": "bulk"}, headers=GUARD).json()["id"]
    for row in direct:
        _send(client, upload_id, row.name, row.data)
    _send(client, upload_id, "site-b.zip", zipped_bytes(zipped))
    assert client.post(f"/api/uploads/{upload_id}/start", headers=GUARD).status_code == 202
    uploaded = time.monotonic() - started
    state = client.app.state  # type: ignore[attr-defined]
    pool = WorkerPool(state.jobs, HANDLERS, workers=default_workers(), secrets=state.worker_secrets)
    pool.run_until_idle(timeout_s=BUDGET_S * 2)
    elapsed = time.monotonic() - started
    print(f"\n100 files: uploaded in {uploaded:.1f} s, all audited in {elapsed:.1f} s")

    files = client.get(f"/api/uploads/{upload_id}").json()["files"]
    assert {f["name"] for f in files} == set(expected)
    outcomes = {}
    for f in files:
        if not f["accepted"]:
            outcomes[f["name"]] = "refused"
            assert f["reason"], f
        elif f["job_state"] == "succeeded":
            outcomes[f["name"]] = "audited"
        else:
            assert f["job_state"] == "failed", f
            assert f["job_error"].startswith(f"{f['name']}: "), f
            outcomes[f["name"]] = "failed"
    assert outcomes == {name: row.outcome for name, row in expected.items()}
    cut = next(f for f in files if f["name"] == "cut-off.xml")
    result = client.get(f"/api/jobs/{cut['job_id']}/result").json()
    assert {r["status"] for r in result["rules"]} <= {"REVIEW", "N/A"}
    assert elapsed < BUDGET_S

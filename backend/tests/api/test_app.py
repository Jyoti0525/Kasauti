"""The web API's shell (TODO M2.01): health, exposure controls, the ``serve`` command."""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import URL
from sqlalchemy.exc import OperationalError

from kasauti.api.app import SECURITY_HEADERS, Settings, create_app
from kasauti.audit import load_kb
from kasauti.cli.main import main
from kasauti.db import (
    SchemaError,
    create_engine,
    current_revision,
    database_url,
    head_revision,
    upgrade,
)

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"


def _migrated(data_dir: Path) -> URL:
    url = database_url(data_dir, environ={})
    engine = create_engine(url)
    upgrade(engine)
    engine.dispose()
    return url


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    var = tmp_path_factory.mktemp("var")
    app = create_app(Settings(packs=PACKS, database=_migrated(var), staging=var / "staging"))
    yield TestClient(app, base_url="http://127.0.0.1:8000")
    app.state.engine.dispose()


def test_health_names_the_knowledge_base_every_audit_would_use(client: TestClient) -> None:
    body = client.get("/api/health").json()
    kb = load_kb(PACKS)
    assert body["status"] == "ok"
    assert (body["kb_version"], body["ruleset_version"]) == (kb.version, kb.ruleset_version)
    assert set(body["vendor_packs"]) >= {"cisco_ios_xe", "fortinet_fortios", "paloalto_panos"}
    assert (body["database"], body["schema_revision"]) == ("sqlite", head_revision())


def test_health_says_so_when_the_database_cant_be_read_without_saying_where(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_engine: object) -> None:
        raise OperationalError("SELECT", {}, Exception("unable to open C:/secret/path.db"))

    monkeypatch.setattr("kasauti.api.app.current_revision", broken)
    response = client.get("/api/health")
    assert response.status_code == 503
    assert response.json() == {"detail": "database unavailable"}
    assert response.headers["X-Frame-Options"] == "DENY"


def test_the_app_refuses_to_start_on_a_database_without_the_current_schema(
    tmp_path: Path,
) -> None:
    with pytest.raises(SchemaError, match="kasauti db upgrade"):
        create_app(
            Settings(
                packs=PACKS, database=database_url(tmp_path, environ={}), staging=tmp_path / "s"
            )
        )


@pytest.mark.parametrize("path", ["/api/health", "/no-such-route"])
def test_every_response_carries_the_security_headers(client: TestClient, path: str) -> None:
    headers = client.get(path).headers
    assert {k: headers[k] for k in SECURITY_HEADERS} == SECURITY_HEADERS
    assert "server" not in headers


@pytest.mark.parametrize(
    ("host", "status"),
    [
        ("127.0.0.1:8000", 200),
        ("localhost:8000", 200),
        # DNS rebinding: a page on attacker.example resolves its own name to 127.0.0.1.
        ("attacker.example", 400),
        ("attacker.example:8000", 400),
    ],
)
def test_only_the_loopback_names_are_answered(client: TestClient, host: str, status: int) -> None:
    response = client.get("/api/health", headers={"host": host})
    assert response.status_code == status
    assert response.headers["X-Frame-Options"] == "DENY"  # refusals carry the headers too


def test_interactive_docs_are_off_and_the_openapi_document_is_served(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404  # Swagger UI would load scripts from a CDN
    assert client.get("/redoc").status_code == 404
    assert client.get("/api/openapi.json").json()["info"]["title"] == "Kasauti"


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])  # noqa: S104 - refused
def test_serve_refuses_every_address_but_loopback(
    host: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["serve", "--host", host]) == 2
    assert "loopback interface only" in capsys.readouterr().err


def test_serve_binds_the_loopback_address_without_revealing_the_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    args = ["serve", "--host", "localhost", "--port", "8123", "--packs", str(PACKS)]
    assert main([*args, "--data-dir", str(tmp_path)]) == 0
    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 8123,
            "server_header": False,
            "proxy_headers": False,
            "log_level": "info",
        }
    ]


def test_serve_rejects_a_port_that_isnt_one(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["serve", "--port", "70000"])
    assert "is not a TCP port" in capsys.readouterr().err


def test_serve_brings_a_sqlite_database_up_to_date_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: app.state.engine.dispose())
    assert main(["serve", "--packs", str(PACKS), "--data-dir", str(tmp_path / "var")]) == 0
    engine = create_engine(database_url(tmp_path / "var", environ={}))
    assert current_revision(engine) == head_revision()
    engine.dispose()


def test_serve_leaves_postgresql_migrations_to_the_operator(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A shared server's schema changes when its DBA runs ``kasauti db upgrade``, never as a
    side effect of starting one of possibly several API processes."""
    monkeypatch.setenv("KASAUTI_DATABASE_URL", "postgresql://k:hunter2@db.example.org/k")
    assert main(["serve", "--packs", str(PACKS)]) == 1
    err = capsys.readouterr().err
    assert "sslmode=verify-full" in err
    assert "hunter2" not in err


JOB_HANDLERS = {"echo": "job_handlers:echo"}
"""From ``tests/jobs/job_handlers.py``; the shipped registry has no kinds until M2.04."""


@pytest.fixture
def job_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    monkeypatch.syspath_prepend(str(REPO / "backend" / "tests" / "jobs"))
    settings = Settings(
        packs=PACKS, database=_migrated(tmp_path), staging=tmp_path / "s", handlers=JOB_HANDLERS
    )
    app = create_app(settings)
    yield app
    app.state.engine.dispose()


def test_a_job_is_reported_by_its_id(job_app: Any) -> None:
    client = TestClient(job_app, base_url="http://127.0.0.1:8000")
    job_id = job_app.state.jobs.enqueue("echo", {"upload": "sha256:ab"})
    body = client.get(f"/api/jobs/{job_id}").json()
    assert (body["id"], body["kind"], body["state"], body["attempts"]) == (
        job_id,
        "echo",
        "queued",
        0,
    )
    assert body["created_at"].endswith("Z")  # UTC, said so
    assert "payload" not in body


@pytest.mark.parametrize(
    ("job_id", "status"),
    [("00000000-0000-4000-8000-000000000000", 404), ("1", 422), ("1' OR '1'='1", 422)],
)
def test_unknown_and_malformed_job_ids(job_app: Any, job_id: str, status: int) -> None:
    client = TestClient(job_app, base_url="http://127.0.0.1:8000")
    assert client.get(f"/api/jobs/{job_id}").status_code == status


def test_a_job_lookup_hides_database_errors(job_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_job_id: str) -> None:
        raise OperationalError("SELECT", {}, Exception("unable to open C:/secret/path.db"))

    monkeypatch.setattr(job_app.state.jobs, "get", broken)
    client = TestClient(job_app, base_url="http://127.0.0.1:8000")
    response = client.get("/api/jobs/00000000-0000-4000-8000-000000000000")
    assert (response.status_code, response.json()) == (503, {"detail": "database unavailable"})


def test_the_server_runs_jobs_in_the_background_while_it_is_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(REPO / "backend" / "tests" / "jobs"))
    settings = Settings(
        packs=PACKS,
        database=_migrated(tmp_path),
        staging=tmp_path / "s",
        handlers=JOB_HANDLERS,
        workers=1,
    )
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:  # runs the lifespan
        assert app.state.pool is not None
        job_id = app.state.jobs.enqueue("echo", {"n": 1})
        app.state.pool.wake()
        deadline = time.monotonic() + 60
        while (body := client.get(f"/api/jobs/{job_id}").json())["state"] != "succeeded":
            assert time.monotonic() < deadline, body
            time.sleep(0.05)
        assert body["result"]["echo"] == {"n": 1}
    assert app.state.pool._thread is None  # stopped with the application


def test_serve_starts_the_worker_pool_it_is_asked_for(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **_kw: apps.append(app))
    base = ["serve", "--packs", str(PACKS), "--data-dir", str(tmp_path)]
    assert main([*base, "--workers", "3"]) == 0
    assert main(base) == 0
    assert main([*base, "--workers", "0"]) == 0
    assert apps[0].state.pool.workers == 3
    assert apps[1].state.pool.workers in (1, 2)
    assert apps[2].state.pool is None
    for app in apps:
        app.state.engine.dispose()


@pytest.mark.parametrize("workers", ["-1", "33", "many"])
def test_serve_rejects_a_worker_count_out_of_range(
    workers: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        main(["serve", "--workers", workers])
    assert "--workers" in capsys.readouterr().err

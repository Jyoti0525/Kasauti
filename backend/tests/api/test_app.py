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

from kasauti.accounts import DEMO_ACCOUNTS
from kasauti.api.app import SECURITY_HEADERS, WEB_CSP, Settings, create_app, public_origin
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
from kasauti.jobs.limits import DEFAULT_MEMORY_MIB
from kasauti.packs.loader import PackError

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


@pytest.mark.parametrize(
    ("text", "origin"),
    [
        ("https://Kasauti.example.org", "https://kasauti.example.org"),
        ("https://kasauti.example.org/", "https://kasauti.example.org"),
        ("https://kasauti.example.org:8443", "https://kasauti.example.org:8443"),
    ],
)
def test_a_public_origin_is_an_https_name_and_nothing_else(text: str, origin: str) -> None:
    assert public_origin(text) == origin


@pytest.mark.parametrize(
    "text",
    [
        "http://kasauti.example.org",  # plain HTTP: the cookie and passwords would travel in clear
        "https://kasauti.example.org/app",
        "https://user@kasauti.example.org",
        "https://kasauti.example.org?x=1",
        "https://kasauti.example.org:99999",
        "kasauti.example.org",
    ],
)
def test_anything_else_is_not_a_public_origin(text: str) -> None:
    with pytest.raises(ValueError, match=r"public origin|port"):
        public_origin(text)


PUBLIC = "https://kasauti.example.org"


@pytest.fixture(scope="module")
def public_client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    var = tmp_path_factory.mktemp("public")
    app = create_app(
        Settings(
            packs=PACKS,
            database=_migrated(var),
            staging=var / "staging",
            demo_accounts=True,
            public_origin=PUBLIC,
        )
    )
    with TestClient(app, base_url="http://kasauti.example.org") as client:
        yield client
    app.state.engine.dispose()


@pytest.mark.parametrize(
    ("host", "status"),
    [
        ("kasauti.example.org", 200),
        ("127.0.0.1:7860", 200),  # the host's own checks, from inside the machine
        ("attacker.example", 400),
        ("kasauti.example.org.attacker.example", 400),
    ],
)
def test_a_public_server_answers_to_its_own_name(
    public_client: TestClient, host: str, status: int
) -> None:
    response = public_client.get("/api/health", headers={"host": host})
    assert response.status_code == status
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"


def test_a_public_server_takes_its_https_origin_as_its_own(public_client: TestClient) -> None:
    body = {"username": "asha", "password": DEMO_ACCOUNTS[0][3]}
    guard = {"X-Kasauti-Request": "1", "Sec-Fetch-Site": "same-origin"}
    other = public_client.post(
        "/api/auth/login", json=body, headers={**guard, "Origin": "http://kasauti.example.org"}
    )
    assert (other.status_code, other.json()) == (403, {"detail": "cross-origin request refused"})
    own = public_client.post("/api/auth/login", json=body, headers={**guard, "Origin": PUBLIC})
    assert own.status_code == 200
    assert "secure" in own.headers["set-cookie"].lower()  # HTTPS in front, so never sent in clear


def test_a_loopback_server_sends_no_hsts(client: TestClient) -> None:
    assert "strict-transport-security" not in client.get("/api/health").headers


def test_serve_public_listens_everywhere_for_its_name_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[Any, dict[str, Any]]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append((app, kw)))
    args = ["serve", "--public", PUBLIC, "--port", "7860", "--packs", str(PACKS)]
    assert main([*args, "--data-dir", str(tmp_path)]) == 0
    [(app, kw)] = calls
    assert (kw["host"], kw["port"], kw["proxy_headers"]) == ("0.0.0.0", 7860, False)  # noqa: S104
    assert app.state.secure_cookie is True
    app.state.engine.dispose()


def test_serve_refuses_a_public_address_that_isnt_https(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["serve", "--public", "http://kasauti.example.org"]) == 2
    assert "not a public origin" in capsys.readouterr().err


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


def signed_in(app: Any, username: str = "asha") -> TestClient:
    """A client of ``app`` (made with ``demo_accounts``) signed in as a demo account."""
    client = TestClient(app, base_url="http://127.0.0.1:8000")
    password = next(p for u, _, _, p in DEMO_ACCOUNTS if u == username)
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-Kasauti-Request": "1"},
    )
    assert response.status_code == 200, response.text
    return client


JOB_HANDLERS = {"echo": "job_handlers:echo"}
"""From ``tests/jobs/job_handlers.py``; the shipped registry has no kinds until M2.04."""


@pytest.fixture
def job_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    monkeypatch.syspath_prepend(str(REPO / "backend" / "tests" / "jobs"))
    settings = Settings(
        packs=PACKS,
        database=_migrated(tmp_path),
        staging=tmp_path / "s",
        handlers=JOB_HANDLERS,
        demo_accounts=True,
    )
    app = create_app(settings)
    yield app
    app.state.engine.dispose()


def test_a_job_is_reported_by_its_id(job_app: Any) -> None:
    client = signed_in(job_app)
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
    client = signed_in(job_app)
    assert client.get(f"/api/jobs/{job_id}").status_code == status


def test_a_job_lookup_hides_database_errors(job_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_job_id: str) -> None:
        raise OperationalError("SELECT", {}, Exception("unable to open C:/secret/path.db"))

    monkeypatch.setattr(job_app.state.jobs, "get", broken)
    client = signed_in(job_app)
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
        demo_accounts=True,
    )
    app = create_app(settings)
    with signed_in(app) as client:  # runs the lifespan
        assert app.state.pool is not None
        job_id = app.state.jobs.enqueue("echo", {"n": 1})
        app.state.pool.wake()
        deadline = time.monotonic() + 60
        while (body := client.get(f"/api/jobs/{job_id}").json())["state"] != "succeeded":
            assert time.monotonic() < deadline, body
            time.sleep(0.05)
        assert body["has_result"]
        assert client.get(f"/api/jobs/{job_id}/result").json()["echo"] == {"n": 1}
    assert app.state.pool._thread is None  # stopped with the application


def test_serve_starts_the_worker_pool_it_is_asked_for(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **_kw: apps.append(app))
    base = ["serve", "--packs", str(PACKS), "--data-dir", str(tmp_path)]
    assert main([*base, "--workers", "3", "--worker-memory", "1024"]) == 0
    assert main(base) == 0
    assert main([*base, "--workers", "0"]) == 0
    assert (apps[0].state.pool.workers, apps[0].state.pool.memory_mib) == (3, 1024)
    assert apps[1].state.pool.workers in (1, 2)
    assert apps[1].state.pool.memory_mib == DEFAULT_MEMORY_MIB
    assert apps[2].state.pool is None
    for app in apps:
        app.state.engine.dispose()


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--workers", "-1"),
        ("--workers", "33"),
        ("--workers", "many"),
        ("--worker-memory", "100"),
        ("--worker-memory", "lots"),
    ],
)
def test_serve_rejects_worker_settings_out_of_range(
    option: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        main(["serve", option, value])
    assert option in capsys.readouterr().err


# -- the web UI (M2.75) -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def web_client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    """An app serving a stand-in build folder, with a file beside it that must never be served."""
    base = tmp_path_factory.mktemp("web")
    dist = base / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>Kasauti</title>", encoding="utf-8")
    (dist / "assets" / "app-1a2b.js").write_text("console.log(1)", encoding="utf-8")
    (dist / "assets" / "app-1a2b.css").write_text("body{}", encoding="utf-8")
    (dist / "assets" / "notes.py").write_text("print('source')", encoding="utf-8")
    (base / "secret.txt").write_text("outside the build folder", encoding="utf-8")
    var = base / "var"
    app = create_app(
        Settings(packs=PACKS, database=_migrated(var), staging=var / "staging", web=dist)
    )
    yield TestClient(app, base_url="http://127.0.0.1:8000")
    app.state.engine.dispose()


@pytest.mark.parametrize("path", ["/", "/audits", "/audits/3f2a/devices/9c1d", "/kb"])
def test_every_page_path_gets_the_app_under_its_own_policy(
    web_client: TestClient, path: str
) -> None:
    response = web_client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.text.startswith("<!doctype html>")
    assert response.headers["Content-Security-Policy"] == WEB_CSP
    assert "'unsafe-inline'" not in WEB_CSP
    assert "'unsafe-eval'" not in WEB_CSP
    assert response.headers["X-Frame-Options"] == "DENY"


def test_built_files_are_served_with_their_own_type(web_client: TestClient) -> None:
    script = web_client.get("/assets/app-1a2b.js")
    assert (script.status_code, script.headers["content-type"]) == (
        200,
        "text/javascript; charset=utf-8",
    )
    assert script.headers["X-Content-Type-Options"] == "nosniff"
    style = web_client.get("/assets/app-1a2b.css")
    assert style.headers["content-type"] == "text/css; charset=utf-8"


@pytest.mark.parametrize(
    "path",
    [
        "/assets/missing.js",  # a missing asset is a 404, not the app's page
        "/assets/notes.py",  # not a type the UI is built of
        "/../secret.txt",
        "/assets/../../secret.txt",
        "/%2e%2e/secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/..%5csecret.txt",
    ],
)
def test_nothing_outside_the_build_is_served(web_client: TestClient, path: str) -> None:
    response = web_client.get(path)
    assert response.status_code == 404
    assert "outside the build folder" not in response.text
    assert "source" not in response.text


def test_api_paths_never_fall_back_to_the_app(web_client: TestClient) -> None:
    missing = web_client.get("/api/no-such-route")
    assert missing.status_code == 404
    assert missing.headers["content-type"] == "application/json"
    assert missing.headers["Content-Security-Policy"] == SECURITY_HEADERS["Content-Security-Policy"]
    health = web_client.get("/api/health")
    assert health.headers["Content-Security-Policy"] == SECURITY_HEADERS["Content-Security-Policy"]


def test_without_a_build_only_the_api_is_served(client: TestClient) -> None:
    assert client.get("/").status_code == 404
    assert client.get("/audits").status_code == 404


def test_serve_refuses_a_folder_with_no_knowledge_base(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Started from the wrong folder, the default ``packs`` isn't there: the server must stop
    and say so, not run with no vendor pack, framework or rule and fail every audit."""
    empty = tmp_path / "packs"
    empty.mkdir()
    assert main(["serve", "--packs", str(empty), "--data-dir", str(tmp_path / "var")]) == 1
    err = capsys.readouterr().err
    assert "no knowledge base here" in err
    assert "no vendor packs (vendors/) and no frameworks (frameworks/) and no rules" in err
    with pytest.raises(PackError, match="run from the repository root or pass --packs"):
        load_kb(tmp_path / "nowhere")

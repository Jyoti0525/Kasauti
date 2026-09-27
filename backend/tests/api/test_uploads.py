"""Upload routes and cross-site protection (TODO M2.04), end to end with real worker processes."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient

from kasauti.api.app import Settings, create_app
from kasauti.api.jobs import accepts_gzip
from kasauti.audit import KnowledgeBase, audit, load_kb
from kasauti.db import create_engine, database_url, upgrade
from kasauti.ingest import upload
from kasauti.ingest.read import decode
from kasauti.jobs import WorkerPool
from kasauti.jobs.kinds import HANDLERS
from kasauti.jobs.results import expand

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"
WEAK = REPO / "datasets" / "authored" / "cisco_ios_xe" / "weak.cfg"
PANOS = REPO / "datasets" / "authored" / "paloalto_panos" / "weak.xml"
HARDENED = WEAK.with_name("hardened.cfg")
SECRETS = re.compile(rb"PLACEHOLDER|\bpublic\b|\bprivate\b")
"""The secrets planted in weak.cfg (as in tests/test_audit.py)."""
GUARD = {"X-Kasauti-Request": "1"}
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


def _new(client: TestClient, **body: Any) -> str:
    response = client.post("/api/uploads", json=body, headers=GUARD)
    assert response.status_code == 201, response.text
    upload_id: str = response.json()["id"]
    return upload_id


def _send(
    client: TestClient, upload_id: str, name: str, data: bytes, **headers: str
) -> httpx.Response:
    return client.post(
        f"/api/uploads/{upload_id}/files",
        content=data,
        headers={
            **GUARD,
            "Content-Type": "application/octet-stream",
            "X-File-Name": name,
            **headers,
        },
    )


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


# -- cross-site protection --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({}, 403),  # a plain form POST from any page could look like this
        ({**GUARD, "Sec-Fetch-Site": "cross-site"}, 403),
        ({**GUARD, "Sec-Fetch-Site": "same-site"}, 403),
        ({**GUARD, "Origin": "http://evil.example"}, 403),
        ({**GUARD, "Origin": "null"}, 403),  # sandboxed frames, file:// pages
        ({**GUARD, "Origin": "http://127.0.0.1:9999"}, 403),  # another local port is another site
        ({"X-Kasauti-Request": "true"}, 403),
        (GUARD, 201),  # a script or the command line
        ({**GUARD, "Sec-Fetch-Site": "same-origin", "Origin": BASE}, 201),  # the web UI
        ({**GUARD, "Sec-Fetch-Site": "none"}, 201),  # typed by the user
    ],
)
def test_state_changing_requests_must_come_from_this_site(
    client: TestClient, headers: dict[str, str], status: int
) -> None:
    response = client.post("/api/uploads", json={}, headers=headers)
    assert response.status_code == status
    if status == 403:
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "access-control-allow-origin" not in response.headers


def test_reading_needs_no_header_and_no_route_answers_a_cors_preflight(
    client: TestClient,
) -> None:
    upload_id = _new(client)
    assert client.get(f"/api/uploads/{upload_id}").status_code == 200
    preflight = client.options(
        "/api/uploads",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-kasauti-request",
        },
    )
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers


# -- creating and filling an upload ----------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ({"frameworks": ["cis_benchmark_fantasy"]}, "not installed: cis_benchmark_fantasy"),
        ({"vendor": "mikrotik_routeros"}, "no vendor pack 'mikrotik_routeros'"),
        ({"frameworks": []}, None),
        ({"label": "x" * 201}, None),
        ({"payload": "extra field"}, None),
    ],
)
def test_an_upload_names_only_what_is_installed(
    client: TestClient, body: dict[str, Any], detail: str | None
) -> None:
    response = client.post("/api/uploads", json=body, headers=GUARD)
    assert response.status_code == 422
    if detail is not None:
        assert detail in response.json()["detail"]


def test_one_request_per_file_and_every_refusal_is_reported(client: TestClient) -> None:
    upload_id = _new(client, label="  Q3 core  ")
    weak = WEAK.read_bytes()
    sent = [
        _send(client, upload_id, "site-a%2Fcore%2Fweak.cfg", weak),
        _send(client, upload_id, "copy.cfg", weak),
        _send(client, upload_id, "logo.png", b"\x89PNG\r\n\x1a\n"),
        _send(client, upload_id, "configs.zip", _zip({"fw/pa.xml": PANOS.read_bytes()})),
    ]
    assert [r.status_code for r in sent] == [201, 201, 201, 201]
    view = client.get(f"/api/uploads/{upload_id}").json()
    assert (view["label"], view["state"], view["accepted"], view["refused"]) == (
        "Q3 core",
        "open",
        2,
        2,
    )
    by_name = {f["name"]: f for f in view["files"]}
    assert by_name["site-a/core/weak.cfg"]["accepted"]
    assert by_name["site-a/core/weak.cfg"]["size"] == len(weak)
    assert by_name["copy.cfg"]["reason"] == "the same content as site-a/core/weak.cfg"
    assert "not a configuration file type" in by_name["logo.png"]["reason"]
    assert by_name["configs.zip/fw/pa.xml"]["accepted"]


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"Content-Type": "multipart/form-data; boundary=x"}, 415),
        ({"Content-Type": "text/plain"}, 415),
    ],
)
def test_a_file_is_sent_as_raw_bytes(
    client: TestClient, headers: dict[str, str], status: int
) -> None:
    upload_id = _new(client)
    assert _send(client, upload_id, "r.cfg", b"hostname R\n", **headers).status_code == status


def test_a_file_needs_a_name_and_an_open_upload(client: TestClient) -> None:
    upload_id = _new(client)
    nameless = client.post(
        f"/api/uploads/{upload_id}/files",
        content=b"hostname R\n",
        headers={**GUARD, "Content-Type": "application/octet-stream"},
    )
    assert nameless.status_code == 422
    missing = "00000000-0000-4000-8000-000000000000"
    assert _send(client, missing, "r.cfg", b"hostname R\n").status_code == 404
    assert _send(client, "not-a-uuid", "r.cfg", b"hostname R\n").status_code == 422
    client.delete(f"/api/uploads/{upload_id}", headers=GUARD)
    gone = _send(client, upload_id, "r.cfg", b"hostname R\n")
    assert (gone.status_code, gone.json()["detail"]) == (409, "this upload was discarded")


def test_a_file_over_the_limit_is_refused_without_being_kept(
    client: TestClient, var: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upload, "MAX_BYTES", 1024 * 1024)
    upload_id = _new(client)
    big = b"hostname R\n" + b"!" * (2 * 1024 * 1024)

    def chunked() -> Iterator[bytes]:  # no Content-Length: the limit is counted while reading
        for at in range(0, len(big), 64 * 1024):
            yield big[at : at + 64 * 1024]

    declared = _send(client, upload_id, "declared.cfg", big).json()["files"][0]
    streamed = _send(client, upload_id, "streamed.cfg", chunked()).json()["files"][0]  # type: ignore[arg-type]
    for row in (declared, streamed):
        assert (row["accepted"], row["reason"]) == (False, "over the 1 MiB limit")
    assert not [p for p in (var / "staging").rglob("*") if p.is_file()]


def test_taking_a_file_back_out_and_discarding(client: TestClient, var: Path) -> None:
    upload_id = _new(client)
    (row,) = _send(client, upload_id, "r.cfg", b"hostname R\n").json()["files"]
    url = f"/api/uploads/{upload_id}/files/{row['id']}"
    assert client.delete(url).status_code == 403
    assert client.delete(url, headers=GUARD).status_code == 204
    assert client.delete(url, headers=GUARD).status_code == 404
    assert client.get(f"/api/uploads/{upload_id}").json()["files"] == []
    assert client.delete(f"/api/uploads/{upload_id}", headers=GUARD).status_code == 204
    assert not (var / "staging" / upload_id).exists()
    assert client.get(f"/api/uploads/{upload_id}").json()["state"] == "discarded"


# -- starting: audits in worker processes ------------------------------------------------------


def _run_jobs(client: TestClient) -> None:
    state = client.app.state  # type: ignore[attr-defined]
    pool = WorkerPool(state.jobs, HANDLERS, workers=2, secrets=state.worker_secrets)
    pool.run_until_idle(timeout_s=120)


def test_upload_to_audit_results_with_no_secret_left_behind(client: TestClient, var: Path) -> None:
    assert len(SECRETS.findall(WEAK.read_bytes())) >= 5, "the scan below needs planted secrets"
    upload_id = _new(client, label="core")
    _send(client, upload_id, "weak.cfg", WEAK.read_bytes())
    _send(client, upload_id, "more.zip", _zip({"pa/weak.xml": PANOS.read_bytes()}))
    # Waiting for their audit, the files are on disk sealed: no planted secret, not even the
    # host name, can be read from them (or recovered once they're deleted).
    waiting = [p for p in (var / "staging").rglob("*") if p.is_file()]
    assert len(waiting) == 2
    for path in waiting:
        assert not SECRETS.search(path.read_bytes())
        assert b"EDGE-R1" not in path.read_bytes()
        assert b"PA-BRANCH" not in path.read_bytes()
    early = client.post(f"/api/uploads/{upload_id}/start", headers=GUARD)
    assert (early.status_code, early.json()["detail"]) == (
        409,
        "2 files are still being recognised; start again when they are",
    )
    _run_jobs(client)  # recognising them
    assert [p for p in (var / "staging").rglob("*") if p.is_file()] == waiting, "still there"
    started = client.post(f"/api/uploads/{upload_id}/start", headers=GUARD)
    assert started.status_code == 202
    assert {f["job_state"] for f in started.json()["files"]} == {"queued"}
    _run_jobs(client)

    view = client.get(f"/api/uploads/{upload_id}").json()
    assert {f["name"]: f["job_state"] for f in view["files"]} == {
        "weak.cfg": "succeeded",
        "more.zip/pa/weak.xml": "succeeded",
    }
    kb = client.app.state.kb  # type: ignore[attr-defined]
    for f, source in zip(view["files"], (WEAK, PANOS), strict=True):
        assert client.get(f"/api/jobs/{f['job_id']}").json()["has_result"]
        response = client.get(f"/api/jobs/{f['job_id']}/result")
        assert response.headers["content-encoding"] == "gzip"  # sent as stored
        expected = audit(decode(source.read_bytes(), f["name"]), kb)
        assert response.json() == json.loads(expected.canonical_json())

    # Nothing unmasked anywhere Kasauti writes: the database (with its WAL) and staging. Results
    # are stored compressed, where a byte scan can't see, so they are scanned expanded too.
    queue = client.app.state.jobs  # type: ignore[attr-defined]
    for f in view["files"]:
        assert not SECRETS.search(b"".join(expand(queue.result(f["job_id"])))), f["name"]
    client.app.state.engine.dispose()  # type: ignore[attr-defined]
    written = [p for p in var.rglob("*") if p.is_file()]
    assert any(p.name == "kasauti.db" for p in written)
    for path in written:
        assert not SECRETS.search(path.read_bytes()), path.name
    assert not [p for p in (var / "staging").rglob("*") if p.is_file()]


def test_a_result_is_expanded_for_a_client_that_refuses_gzip(client: TestClient) -> None:
    upload_id = _new(client)
    _send(client, upload_id, "weak.cfg", WEAK.read_bytes())
    _run_jobs(client)
    (row,) = client.post(f"/api/uploads/{upload_id}/start", headers=GUARD).json()["files"]
    early = client.get(f"/api/jobs/{row['job_id']}/result")
    assert (early.status_code, early.json()["detail"]) == (
        409,
        "the job has no result; it is queued",
    )
    _run_jobs(client)
    url = f"/api/jobs/{row['job_id']}/result"
    zipped = client.get(url)
    plain = client.get(url, headers={"Accept-Encoding": "identity"})
    assert "content-encoding" not in plain.headers
    assert plain.headers["vary"] == "Accept-Encoding"
    assert plain.headers["content-type"] == "application/json"
    assert plain.json() == zipped.json()
    assert client.get(f"/api/jobs/{upload_id}/result").status_code == 404  # not a job id


@pytest.mark.parametrize(
    ("header", "gzip"),
    [
        (None, False),
        ("", False),
        ("identity", False),
        ("gzip", True),
        ("GZip", True),
        ("deflate, gzip;q=0.5", True),
        ("gzip;q=0", False),
        ("gzip; q=0.0, *", False),  # named and refused beats the wildcard
        ("*", True),
        ("*;q=0", False),
        ("x-gzip", True),
        ("gzip;q=nope", False),
        ("br, zstd", False),
    ],
)
def test_gzip_is_sent_only_when_accepted(header: str | None, gzip: bool) -> None:
    assert accepts_gzip(header) is gzip


def test_a_started_upload_takes_no_more_files_and_starts_once(client: TestClient) -> None:
    upload_id = _new(client)
    empty = client.post(f"/api/uploads/{upload_id}/start", headers=GUARD)
    assert (empty.status_code, empty.json()["detail"]) == (
        409,
        "nothing to audit: no file in this upload was accepted",
    )
    _send(client, upload_id, "r.cfg", WEAK.read_bytes())
    _run_jobs(client)
    assert client.post(f"/api/uploads/{upload_id}/start", headers=GUARD).status_code == 202
    assert client.post(f"/api/uploads/{upload_id}/start", headers=GUARD).status_code == 409
    assert _send(client, upload_id, "late.cfg", b"hostname L\n").status_code == 409


def test_an_unrecognised_file_fails_its_audit_with_a_reason(client: TestClient) -> None:
    upload_id = _new(client)
    _send(client, upload_id, "mystery.txt", b"just some words\n")
    _run_jobs(client)
    (row,) = client.get(f"/api/uploads/{upload_id}").json()["files"]
    assert (row["kind"], row["paired_by"], row["device"]) == ("unknown", "alone", row["id"])
    client.post(f"/api/uploads/{upload_id}/start", headers=GUARD)
    _run_jobs(client)
    (row,) = client.get(f"/api/uploads/{upload_id}").json()["files"]
    assert row["job_state"] == "failed"
    assert row["job_error"].startswith("mystery.txt: can't tell which vendor this is")


def test_devices_and_pairing_by_hand(client: TestClient) -> None:
    upload_id = _new(client)
    companions = REPO / "datasets" / "authored" / "cisco_ios_xe" / "companions"
    running = _send(client, upload_id, "running.cfg", WEAK.read_bytes()).json()["files"][0]
    startup = _send(client, upload_id, "startup.cfg", HARDENED.read_bytes()).json()["files"][0]
    sent = _send(client, upload_id, "version.txt", (companions / "show_version.txt").read_bytes())
    version = sent.json()["files"][0]
    assert version["recognition"] == "pending"
    url = f"/api/uploads/{upload_id}/files/{version['id']}/pairing"
    waiting = client.put(url, json={"config": running["id"]}, headers=GUARD)
    assert (waiting.status_code, waiting.json()["detail"]) == (
        409,
        "version.txt is still being recognised; try again shortly",
    )
    _run_jobs(client)

    view = client.get(f"/api/uploads/{upload_id}").json()
    assert view["recognising"] == 0
    rows = {f["name"]: f for f in view["files"]}
    assert {k: rows["version.txt"][k] for k in ("kind", "vendor", "command", "hostname")} == {
        "kind": "companion",
        "vendor": "cisco_ios_xe",
        "command": "show_version",
        "hostname": "EDGE-R1",
    }
    assert rows["version.txt"]["device"] is None, "two configurations are host EDGE-R1"
    assert "pair it by hand" in rows["version.txt"]["note"]

    paired = client.put(url, json={"config": startup["id"]}, headers=GUARD)
    assert paired.status_code == 200
    assert paired.json()["devices"] == [
        {
            "config": running["id"],
            "name": "running.cfg",
            "vendor": "cisco_ios_xe",
            "hostname": "EDGE-R1",
            "companions": [],
        },
        {
            "config": startup["id"],
            "name": "startup.cfg",
            "vendor": "cisco_ios_xe",
            "hostname": "EDGE-R1",
            "companions": [version["id"]],
        },
    ]
    wrong = client.put(
        f"/api/uploads/{upload_id}/files/{running['id']}/pairing",
        json={"config": startup["id"]},
        headers=GUARD,
    )
    assert wrong.status_code == 422
    assert wrong.json()["detail"].startswith("only command outputs are paired; running.cfg is")
    missing = client.put(url, json={"config": str(uuid.uuid4())}, headers=GUARD)
    assert (missing.status_code, missing.json()["detail"]) == (404, "no such file in this upload")
    assert client.put(url, json={"config": startup["id"]}).status_code == 403  # no guard header

    started = client.post(f"/api/uploads/{upload_id}/start", headers=GUARD).json()
    jobs_by_name = {f["name"]: f["job_id"] for f in started["files"]}
    assert jobs_by_name["version.txt"] == jobs_by_name["startup.cfg"] != jobs_by_name["running.cfg"]
    _run_jobs(client)
    result = client.get(f"/api/jobs/{jobs_by_name['startup.cfg']}/result").json()
    assert [(c["file"], c["used"]) for c in result["companions"]] == [("version.txt", True)]
    assert result["identity"]["serial"]["value"] is not None
    assert client.delete(url, headers=GUARD).status_code == 409, "started: no more changes"


# -- the installed command -------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def test_the_installed_kasauti_serve_runs_an_upload_to_its_audit(tmp_path: Path) -> None:
    """Worker processes are spawned; under the console-script launcher (an .exe on Windows) that
    must work as it does under pytest. This runs the real command end to end."""
    command = shutil.which("kasauti", path=str(Path(sys.executable).parent))
    assert command is not None, "the kasauti console script isn't installed"
    port = _free_port()
    env = {**os.environ, "KASAUTI_DATA_DIR": str(tmp_path)}
    env.pop("KASAUTI_DATABASE_URL", None)
    server = subprocess.Popen(
        [
            *(command, "serve", "--port", str(port), "--packs", str(PACKS)),
            *("--workers", "1", "--worker-memory", "1024"),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10) as http:
            deadline = time.monotonic() + 30
            while True:
                try:
                    if http.get("/api/health").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert time.monotonic() < deadline, "the server didn't come up"
                time.sleep(0.2)
            upload_id = http.post("/api/uploads", json={}, headers=GUARD).json()["id"]
            http.post(
                f"/api/uploads/{upload_id}/files",
                content=WEAK.read_bytes(),
                headers={
                    **GUARD,
                    "Content-Type": "application/octet-stream",
                    "X-File-Name": "w.cfg",
                },
            )
            deadline = time.monotonic() + 60
            while http.get(f"/api/uploads/{upload_id}").json()["recognising"]:
                assert time.monotonic() < deadline, "the file wasn't recognised"
                time.sleep(0.2)
            assert http.post(f"/api/uploads/{upload_id}/start", headers=GUARD).status_code == 202
            while (row := http.get(f"/api/uploads/{upload_id}").json()["files"][0])[
                "job_state"
            ] in {"queued", "running"}:
                assert time.monotonic() < deadline, "the audit didn't finish"
                time.sleep(0.2)
            assert (row["job_state"], row["job_error"]) == ("succeeded", None)
            result = http.get(f"/api/jobs/{row['job_id']}/result")
            assert result.headers["content-encoding"] == "gzip"
            assert result.json()["detection"]["pack_id"] == "cisco_ios_xe"
    finally:
        server.terminate()
        server.wait(timeout=30)

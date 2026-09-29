"""Team accounts: sign-in, sign-up, sessions and roles (PLAN §17; TODO M5.03-M5.05)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kasauti.accounts import DEMO_ACCOUNTS, AccountStore, Role
from kasauti.accounts.store import IDLE, LIFETIME, MAX_FAILURES
from kasauti.accounts.table import accounts, sessions
from kasauti.api.app import Settings, create_app
from kasauti.api.auth import COOKIE
from kasauti.audit import KnowledgeBase
from kasauti.cli.main import main
from kasauti.db import create_engine, database_url

REPO = Path(__file__).resolve().parents[3]
BASE = "http://127.0.0.1:8000"
GUARD = {"X-Kasauti-Request": "1"}


def _app(var: Path, kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch, **settings: Any) -> Any:
    monkeypatch.setattr("kasauti.api.app.load_kb", lambda _packs, _learned=None: kb)
    return create_app(
        Settings(
            packs=REPO / "packs",
            database=database_url(var, environ={}),
            staging=var / "staging",
            **settings,
        )
    )


@pytest.fixture
def anon(var: Path, kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Not signed in, on a server with the demo accounts."""
    with TestClient(_app(var, kb, monkeypatch, demo_accounts=True), base_url=BASE) as client:
        yield client


def _login(client: TestClient, username: str, password: str) -> Any:
    return client.post(
        "/api/auth/login", json={"username": username, "password": password}, headers=GUARD
    )


def test_everything_but_health_and_sign_in_needs_a_session(anon: TestClient) -> None:
    assert anon.get("/api/health").status_code == 200
    assert anon.get("/api/auth/options").status_code == 200
    for method, path in [
        ("GET", "/api/audits"),
        ("GET", "/api/studio"),
        ("GET", "/api/jobs/00000000-0000-4000-8000-000000000000"),
        ("POST", "/api/uploads"),
        ("GET", "/api/auth/me"),
    ]:
        response = anon.request(method, path, json={}, headers=GUARD)
        assert (response.status_code, response.json()) == (401, {"detail": "sign in first"}), path


def test_signing_in_sets_a_cookie_scripts_and_other_sites_cant_use(anon: TestClient) -> None:
    response = _login(anon, "asha", "Kasauti-Demo-Trainer")
    assert response.json() == {"username": "asha", "name": "Asha", "role": "trainer"}
    cookie = response.headers["set-cookie"].lower()
    assert f"{COOKIE}=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert anon.get("/api/audits").status_code == 200
    # Signing in is a change like any other: another site's page can't do it for the browser.
    assert anon.post("/api/auth/login", json={"username": "asha", "password": "x"}).status_code == (
        403
    )


def test_signing_out_ends_the_session_on_the_server(anon: TestClient) -> None:
    _login(anon, "ravi", "Kasauti-Demo-Approver")
    token = anon.cookies[COOKIE]
    assert anon.post("/api/auth/logout", headers=GUARD).status_code == 204
    assert anon.get("/api/auth/me").status_code == 401
    anon.cookies.set(COOKIE, token)  # a copy of the old cookie signs no one in
    assert anon.get("/api/auth/me").status_code == 401


def test_wrong_passwords_lock_the_account_for_a_while(anon: TestClient) -> None:
    unknown = _login(anon, "nobody", "whatever it may be")
    wrong = _login(anon, "asha", "not her password at all")
    # The same answer whether the name exists or not.
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json() == {"detail": "wrong username or password"}
    for _ in range(MAX_FAILURES - 1):
        _login(anon, "asha", "not her password at all")
    locked = _login(anon, "asha", "Kasauti-Demo-Trainer")  # right, but too late
    assert locked.status_code == 401
    assert "locked" in locked.json()["detail"]
    assert _login(anon, "ravi", "Kasauti-Demo-Approver").status_code == 200  # others unaffected


def test_sign_up_makes_an_auditor_with_a_long_password(anon: TestClient) -> None:
    body = {"username": "Kiran", "name": "Kiran  Rao", "password": "short"}
    short = anon.post("/api/auth/signup", json=body, headers=GUARD)
    assert (short.status_code, "at least 15" in short.json()["detail"]) == (409, True)
    easy = anon.post(
        "/api/auth/signup", json={**body, "password": "kiran" + "x" * 15}, headers=GUARD
    )
    assert easy.status_code == 409
    made = anon.post(
        "/api/auth/signup", json={**body, "password": "correct horse battery"}, headers=GUARD
    )
    assert made.status_code == 201
    assert made.json() == {"username": "kiran", "name": "Kiran Rao", "role": "auditor"}
    # Signed in, and an auditor may start an audit.
    assert anon.post("/api/uploads", json={}, headers=GUARD).status_code == 201
    taken = anon.post(
        "/api/auth/signup", json={**body, "password": "another long phrase"}, headers=GUARD
    )
    assert (taken.status_code, taken.json()["detail"]) == (409, "the username 'kiran' is taken")


def test_a_viewer_reads_but_changes_nothing(anon: TestClient) -> None:
    store: AccountStore = anon.app.state.accounts  # type: ignore[attr-defined]
    store.create("vani", "Vani", "only-looking-around-here", Role.VIEWER)
    assert _login(anon, "vani", "only-looking-around-here").status_code == 200
    assert anon.get("/api/audits").status_code == 200
    refused = anon.post("/api/uploads", json={}, headers=GUARD)
    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "this needs the auditor role; you are viewer",
    )


def test_passwords_and_tokens_are_stored_only_as_hashes(anon: TestClient) -> None:
    _login(anon, "asha", "Kasauti-Demo-Trainer")
    token = anon.cookies[COOKIE]
    engine = anon.app.state.engine  # type: ignore[attr-defined]
    with engine.connect() as conn:
        hashes = [r.password_hash for r in conn.execute(select(accounts))]
        ids = [r.id for r in conn.execute(select(sessions))]
    assert hashes
    assert all(h.startswith("$argon2id$") for h in hashes)
    assert not any(p in h for h in hashes for *_, p in DEMO_ACCOUNTS)
    assert token not in ids
    assert len(ids) == 1


def test_demo_passwords_are_shown_only_when_asked_for(
    anon: TestClient, var: Path, kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shown = anon.get("/api/auth/options").json()
    assert shown["signup"] is True
    assert [(d["username"], d["role"]) for d in shown["demo"]] == [
        ("asha", "trainer"),
        ("ravi", "approver"),
    ]
    other = tmp_path / "other"
    other.mkdir()
    (other / "kasauti.db").write_bytes((var / "kasauti.db").read_bytes())
    with TestClient(_app(other, kb, monkeypatch, signup=False), base_url=BASE) as plain:
        assert plain.get("/api/auth/options").json() == {
            "signup": False,
            "min_password": 15,
            "demo": [],
        }
        body = {"username": "kiran", "name": "Kiran", "password": "correct horse battery"}
        assert plain.post("/api/auth/signup", json=body, headers=GUARD).status_code == 403


def test_a_session_ends_when_idle_and_after_its_lifetime(anon: TestClient) -> None:
    store: AccountStore = anon.app.state.accounts  # type: ignore[attr-defined]
    asha = store.verify("asha", "Kasauti-Demo-Trainer")
    # Ahead of the real clock, which the server's housekeeping runs on meanwhile.
    start = dt.datetime.now(dt.UTC) + dt.timedelta(days=1)
    idle = store.start_session(asha, now=start)
    assert store.session(idle, now=start + IDLE - dt.timedelta(seconds=1)) == asha
    assert store.session(idle, now=start + 2 * IDLE) is None
    busy = store.start_session(asha, now=start)
    moment = start
    while moment + IDLE / 2 < start + LIFETIME:
        moment += IDLE / 2
        assert store.session(busy, now=moment) == asha
    assert store.session(busy, now=start + LIFETIME) is None


def test_the_command_line_adds_accounts_and_sets_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KASAUTI_PASSWORD", "the first administrator")
    monkeypatch.delenv("KASAUTI_DATABASE_URL", raising=False)
    data = ["--data-dir", str(tmp_path)]
    assert main(["account", "add", "meera", "--name", "Meera", "--role", "admin", *data]) == 0
    assert main(["account", "role", "meera", "viewer", *data]) == 0
    assert main(["account", "role", "nobody", "admin", *data]) == 1
    out = capsys.readouterr()
    assert "meera: account made, role admin" in out.out
    assert "meera: role viewer" in out.out
    assert "no account 'nobody'" in out.err
    engine = create_engine(database_url(tmp_path, environ={}))
    try:
        store = AccountStore(engine)
        assert store.verify("meera", "the first administrator").role is Role.VIEWER
    finally:
        engine.dispose()

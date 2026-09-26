"""The web API's shell (TODO M2.01): health, exposure controls, the ``serve`` command."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient

from kasauti.api.app import SECURITY_HEADERS, Settings, create_app
from kasauti.audit import load_kb
from kasauti.cli.main import main

REPO = Path(__file__).resolve().parents[3]
PACKS = REPO / "packs"


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app(Settings(packs=PACKS)), base_url="http://127.0.0.1:8000")


def test_health_names_the_knowledge_base_every_audit_would_use(client: TestClient) -> None:
    body = client.get("/api/health").json()
    kb = load_kb(PACKS)
    assert body["status"] == "ok"
    assert (body["kb_version"], body["ruleset_version"]) == (kb.version, kb.ruleset_version)
    assert set(body["vendor_packs"]) >= {"cisco_ios_xe", "fortinet_fortios", "paloalto_panos"}


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    assert main(["serve", "--host", "localhost", "--port", "8123", "--packs", str(PACKS)]) == 0
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

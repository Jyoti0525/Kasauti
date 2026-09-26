"""The web API application (PLAN §4.2, §17; TODO M2.01).

A thin adapter: it loads the knowledge base once and hands requests to the pure pipeline core,
the same core ``kasauti audit`` uses. Routes arrive milestone by milestone (uploads M2.04,
jobs M2.03); this module sets up what every route inherits.

Exposure (PLAN §17, "Exposure" and "Air gap"):

* **Loopback only.** ``kasauti serve`` binds 127.0.0.1 and refuses any other address. Accounts,
  MFA and TLS arrive in M5; serving configurations to the LAN before then would hand them to
  anyone who can reach the port.
* **Host allow-list.** A web page on any site can make a browser send requests to
  ``127.0.0.1`` through a domain it controls (DNS rebinding). Requests whose ``Host`` isn't
  the name the server was started for are refused with 400.
* **Security headers** on every response, errors included: nothing sniffed, framed, cached or
  sent as a referrer, and a content security policy that allows nothing (the API returns JSON;
  the web UI, M2.75, sets its own policy).
* **No interactive docs.** Swagger UI and ReDoc load their scripts from a CDN, and the platform
  makes no network calls. The OpenAPI document is served at ``/api/openapi.json``.

Storage (M2.02): the application opens the database it is given and refuses to start unless the
schema is the one this version expects; migrating is ``kasauti db upgrade``'s job (``kasauti
serve`` runs it first for SQLite).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import URL, Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from kasauti import __version__
from kasauti.audit import KnowledgeBase, load_kb
from kasauti.db import create_engine, current_revision, ensure_current
from kasauti.log import get_logger

log = get_logger(__name__)

LOOPBACK_HOSTS = ("127.0.0.1", "localhost")
"""Host names a loopback-bound server answers to. IPv6 ``[::1]`` isn't offered: Starlette's host
check can't parse a bracketed address, and a check that can't be relied on isn't offered."""

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@dataclass(frozen=True, slots=True)
class Settings:
    packs: Path
    """Knowledge base root (``packs/``)."""
    database: URL
    """From :func:`kasauti.db.database_url`."""
    allowed_hosts: tuple[str, ...] = LOOPBACK_HOSTS


class Health(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str
    kasauti_version: str
    kb_version: str
    """SHA-256 over every pack file, as in every audit result."""
    ruleset_version: str
    vendor_packs: tuple[str, ...]
    frameworks: tuple[str, ...]
    database: str
    """``sqlite`` or ``postgresql``; never the URL, which may name a host or file path."""
    schema_revision: str


def create_app(settings: Settings) -> FastAPI:
    """Build the application. The knowledge base and database are checked here, so invalid
    packs or an old schema stop the server from starting instead of failing on a request."""
    kb = load_kb(settings.packs)
    engine = create_engine(settings.database)
    try:
        ensure_current(engine)
    except BaseException:
        engine.dispose()
        raise

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="Kasauti",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.kb = kb
    app.state.engine = engine
    # Starlette runs the middleware added last first: the headers wrap the host check, so its
    # 400 responses carry them too.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/api/health", responses={503: {"description": "the database can't be read"}})
    def health() -> Health:
        try:
            revision = current_revision(engine)
        except SQLAlchemyError as err:
            # The error names the file or host: the operator's log gets it, the client doesn't.
            log.exception("database unavailable", error=str(err))
            raise HTTPException(503, "database unavailable") from None
        return _health(kb, engine, revision or "none")

    return app


def _health(kb: KnowledgeBase, engine: Engine, revision: str) -> Health:
    return Health(
        status="ok",
        kasauti_version=__version__,
        kb_version=kb.version,
        ruleset_version=kb.ruleset_version,
        vendor_packs=tuple(sorted(kb.vendor_packs)),
        frameworks=tuple(sorted(kb.frameworks)),
        database=engine.dialect.name,
        schema_revision=revision,
    )

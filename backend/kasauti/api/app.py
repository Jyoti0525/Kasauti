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
* **Cross-site requests refused.** Any web page can make the browser send a POST to
  ``127.0.0.1``, even though it can't read the answer. Every request that changes something
  (POST, PUT, PATCH, DELETE) must carry ``X-Kasauti-Request: 1``: a page on another site can only
  add a custom header after a CORS preflight, which this server never grants. On top of that, a
  browser's ``Sec-Fetch-Site`` must say same-origin, and an ``Origin``, when sent, must be this
  server. Sign-in sessions and their CSRF tokens join these in M5.
* **Security headers** on every response, errors included: nothing sniffed, framed, cached or
  sent as a referrer, and a content security policy that allows nothing (the API returns JSON;
  the web UI, M2.75, sets its own policy).
* **No interactive docs.** Swagger UI and ReDoc load their scripts from a CDN, and the platform
  makes no network calls. The OpenAPI document is served at ``/api/openapi.json``.

Storage (M2.02): the application opens the database it is given and refuses to start unless the
schema is the one this version expects; migrating is ``kasauti db upgrade``'s job (``kasauti
serve`` runs it first for SQLite).

Jobs (M2.03): with ``workers`` set, a :class:`~kasauti.jobs.WorkerPool` runs queued jobs in the
background for the application's lifetime; at shutdown, jobs still running go back to the queue.
``GET /api/jobs/{id}`` reports a job (:mod:`kasauti.api.jobs`).

Uploads (M2.04): :mod:`kasauti.api.uploads`. Uploaded files wait in the staging directory until
their audit reads them; a housekeeping task deletes whatever nothing needs any more, at start-up
and every :data:`HOUSEKEEPING_S` seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import URL, Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kasauti import __version__
from kasauti.api.jobs import router as jobs_router
from kasauti.api.uploads import router as uploads_router
from kasauti.audit import KnowledgeBase, load_kb
from kasauti.db import create_engine, current_revision, ensure_current
from kasauti.ingest.staging import Staging
from kasauti.ingest.store import UploadStore
from kasauti.jobs import JobQueue, WorkerPool
from kasauti.jobs.kinds import HANDLERS
from kasauti.jobs.limits import DEFAULT_MEMORY_MIB
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
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
REQUEST_HEADER = "X-Kasauti-Request"
HOUSEKEEPING_S = 60.0


@dataclass(frozen=True, slots=True)
class Settings:
    packs: Path
    """Knowledge base root (``packs/``)."""
    database: URL
    """From :func:`kasauti.db.database_url`."""
    staging: Path
    """Where uploaded files wait for their audit (``<data dir>/staging``)."""
    allowed_hosts: tuple[str, ...] = LOOPBACK_HOSTS
    workers: int = 0
    """Worker processes for background jobs; 0 runs none (jobs wait in the queue)."""
    worker_memory_mib: int = DEFAULT_MEMORY_MIB
    """Memory each worker may use (:mod:`kasauti.jobs.limits`)."""
    handlers: Mapping[str, str] = field(default_factory=lambda: HANDLERS)
    """Job kind to ``module:function``; :data:`kasauti.jobs.kinds.HANDLERS` unless testing."""


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
        queue = JobQueue(engine, settings.handlers)
        staging = Staging(settings.staging)
        staging.prepare()
        store = UploadStore(engine, staging)
        pool = (
            WorkerPool(
                queue,
                settings.handlers,
                workers=settings.workers,
                memory_mib=settings.worker_memory_mib,
            )
            if settings.workers
            else None
        )
    except BaseException:
        engine.dispose()
        raise

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if pool is not None:
            pool.start()
        housekeeping = asyncio.create_task(_housekeep(store))
        try:
            yield
        finally:
            housekeeping.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await housekeeping
            try:
                if pool is not None:
                    pool.stop()
            finally:  # even if handing jobs back failed (the database went away)
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
    app.state.jobs = queue
    app.state.pool = pool
    app.state.uploads = store
    app.state.packs = settings.packs
    # Starlette runs the middleware added last first: the headers wrap the host check, which
    # wraps the cross-site check, so the refusals of both carry the headers.
    app.add_middleware(CrossSiteGuard)
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

    app.include_router(jobs_router)
    app.include_router(uploads_router)
    return app


class CrossSiteGuard:
    """Refuses a state-changing request a web page on another site could have made the browser
    send (see the module docstring). Plain ASGI, so request bodies stream through untouched."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in UNSAFE_METHODS:
            reason = cross_site(Headers(scope=scope))
            if reason is not None:
                await JSONResponse({"detail": reason}, status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def cross_site(headers: Headers) -> str | None:
    """Why this state-changing request is refused, or None."""
    site = headers.get("sec-fetch-site")
    if site is not None and site not in {"same-origin", "none"}:
        return "cross-site request refused"
    origin = headers.get("origin")
    if origin is not None and origin != f"http://{headers.get('host', '')}":
        return "cross-origin request refused"
    if headers.get(REQUEST_HEADER.lower()) != "1":
        return f"requests that change something need the header {REQUEST_HEADER}: 1"
    return None


async def _housekeep(store: UploadStore) -> None:
    while True:
        try:
            removed = await run_in_threadpool(store.housekeep)
            if removed:
                log.info("staged files deleted", files=removed)
        except SQLAlchemyError as err:
            log.warning("housekeeping can't reach the database", error=type(err).__name__)
        except Exception:
            log.exception("housekeeping failed")
        await asyncio.sleep(HOUSEKEEPING_S)


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

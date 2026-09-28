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
  sent as a referrer, and a content security policy that allows nothing for the API, which
  returns JSON.
* **The web UI** (M2.75) is served from the same origin, when it is built (``frontend/dist``),
  so it needs no CORS and passes the cross-site checks as the page the server itself sent. Its
  pages get their own policy (:data:`WEB_CSP`): scripts, styles, fonts and requests from this
  server only, no inline script, no framing, no plugins. Only files inside the build folder
  with a known type are served; any other path that isn't under ``/api`` gets the app's page,
  which routes it in the browser.
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
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import URL, Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from kasauti import __version__
from kasauti.api.audits import router as audits_router
from kasauti.api.jobs import router as jobs_router
from kasauti.api.uploads import router as uploads_router
from kasauti.audit import KnowledgeBase, load_kb
from kasauti.db import create_engine, current_revision, ensure_current
from kasauti.ingest.sealed import new_key
from kasauti.ingest.staging import STAGING_KEY_NAME, Staging
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
WEB_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
"""The web UI's policy. ``data:`` images are the icons the build inlines."""
WEB_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".json": "application/json",
    ".txt": "text/plain; charset=utf-8",
}
"""What the web UI's build folder may serve, typed here: the operating system's own table
(the Windows registry, say) may call a script ``text/plain``, which ``nosniff`` then refuses."""
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
    web: Path | None = None
    """The web UI's build folder (``frontend/dist``); None, or no ``index.html`` in it, serves
    the API alone."""


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
        queue, store, pool, worker_secrets = _jobs_and_uploads(settings, engine)
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
    app.state.worker_secrets = worker_secrets
    app.state.uploads = store
    app.state.packs = settings.packs
    web = (
        settings.web.resolve() if settings.web and (settings.web / "index.html").is_file() else None
    )
    _guard(app, settings.allowed_hosts, web=web is not None)

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
    app.include_router(audits_router)
    if web is not None:
        _serve_web(app, web)
    return app


def _guard(app: FastAPI, allowed_hosts: tuple[str, ...], *, web: bool) -> None:
    """The protections every request passes (module docstring); with ``web``, pages outside
    ``/api`` get the web UI's policy. Starlette runs the middleware added last first: the
    headers wrap the host check, which wraps the cross-site check, so the refusals of both carry
    the headers."""
    app.add_middleware(CrossSiteGuard)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if web and not _is_api(request.url.path):
            response.headers["Content-Security-Policy"] = WEB_CSP
        return response


def _is_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _serve_web(app: FastAPI, root: Path) -> None:
    """The web UI's files, and its page for every other path outside ``/api``."""
    index = root / "index.html"

    @app.get("/{path:path}", include_in_schema=False)
    def web(path: str) -> Response:
        if _is_api(f"/{path}"):
            raise HTTPException(404, "Not Found")
        if path:
            try:
                target = (root / path).resolve()
            except (OSError, ValueError):
                raise HTTPException(404, "Not Found") from None
            kind = WEB_TYPES.get(target.suffix.lower())
            if target.is_relative_to(root) and target.is_file() and kind is not None:
                return FileResponse(target, media_type=kind)
            if target.suffix:  # a file that isn't there, or isn't served: not the app's page
                raise HTTPException(404, "Not Found")
        return FileResponse(index, media_type=WEB_TYPES[".html"])


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


def _jobs_and_uploads(
    settings: Settings, engine: Engine
) -> tuple[JobQueue, UploadStore, WorkerPool | None, dict[str, bytes]]:
    """The job queue, the upload store and the worker pool. Staged uploads are sealed under a
    key made here and kept in memory only (TODO M5.01, first part); workers get it from the
    pool when they start, never through the database."""
    queue = JobQueue(engine, settings.handlers)
    staging_key = new_key()
    staging = Staging(settings.staging, staging_key)
    staging.prepare()
    worker_secrets = {STAGING_KEY_NAME: staging_key}
    pool = (
        WorkerPool(
            queue,
            settings.handlers,
            workers=settings.workers,
            memory_mib=settings.worker_memory_mib,
            secrets=worker_secrets,
        )
        if settings.workers
        else None
    )
    return queue, UploadStore(engine, staging, queue, settings.packs), pool, worker_secrets


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

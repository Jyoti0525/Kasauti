"""Upload routes (PLAN §5.1, §18.1 "New audit"; TODO M2.04, M2.06).

The flow the "New audit" screen follows, and any script can too::

    POST   /api/uploads                     {"label", "frameworks", "vendor"}  -> the upload
    POST   /api/uploads/{id}/files          one file's bytes (or a .zip)       -> its rows
    DELETE /api/uploads/{id}/files/{file}   take a file back out
    GET    /api/uploads/{id}                files, refusals, devices, each audit's state
    PUT    /api/uploads/{id}/files/{file}/pairing  {"config": id or null}      -> the upload
    DELETE /api/uploads/{id}/files/{file}/pairing  back to automatic           -> the upload
    DELETE /api/uploads/{id}                discard the upload
    POST   /api/uploads/{id}/start          queue one audit per device         -> the upload
    GET    /api/jobs/{job}                  an audit's result

Each accepted file is recognised in a worker as it arrives (configuration or command output,
vendor, hostname), and the upload lists the devices that makes: each configuration with the
command outputs that go with it (:mod:`kasauti.ingest.devices`). ``recognising`` counts files
not yet recognised; start when it is 0 (until then, starting answers 409). An output paired
wrongly, or not at all, is paired by hand with ``PUT .../pairing``; ``{"config": null}`` leaves
it out of every audit.

A file is sent as the raw request body (``Content-Type: application/octet-stream``) with its
name, percent-encoded UTF-8, in ``X-File-Name``: one request per file. A folder is its files
sent one by one, each named by its path in the folder. Raw bodies, not multipart forms, so the
server never parses a multipart envelope or spools parts to the system's temporary directory,
and each file is streamed straight to the staging area under its size limit.

A file that is refused (wrong type, empty, binary, too large, a duplicate) still gets a row
with the reason, and the request succeeds: HTTP errors are for requests that are wrong, not for
files that are. Every state-changing request passes the cross-site checks in
:mod:`kasauti.api.app`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from collections.abc import AsyncIterator, Callable
from io import RawIOBase
from typing import Annotated, Any
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from kasauti.ingest.devices import How, Kind
from kasauti.ingest.store import (
    DeviceView,
    FileNotInUploadError,
    FileView,
    PairingError,
    Recognition,
    UploadNotFoundError,
    UploadStateError,
    UploadStore,
    UploadView,
)
from kasauti.ingest.table import LABEL_LIMIT, UploadState
from kasauti.ingest.upload import (
    CHUNK,
    Received,
    body_limit,
    display_name,
    inspect,
    new_id,
    type_refusal,
)
from kasauti.jobs import JobState
from kasauti.log import get_logger
from kasauti.rules.scoring import NIST

log = get_logger(__name__)

FILE_NAME_HEADER = "X-File-Name"
BODY_TYPE = "application/octet-stream"

router = APIRouter(prefix="/api/uploads", tags=["uploads"])


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class UploadIn(_Model):
    label: Annotated[str, Field(max_length=LABEL_LIMIT)] | None = None
    frameworks: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)] = (NIST,)
    vendor: Annotated[str, Field(max_length=64)] | None = None
    """A vendor pack id; leave empty to recognise each file by its fingerprint."""


class FileOut(_Model):
    id: str
    name: str
    """For display only: the file's name or its path in the folder or archive."""
    size: int
    sha256: str | None
    accepted: bool
    reason: str | None
    """Why it was refused, when it was."""
    job_id: str | None
    """Its device's audit, once the upload is started (a command output's too)."""
    job_state: JobState | None
    job_error: str | None
    recognition: Recognition | None
    """For an accepted file: ``pending`` until recognised, then ``done`` or ``failed``."""
    kind: Kind | None
    """``config``, ``companion`` (a command output) or ``unknown``."""
    vendor: str | None
    command: str | None
    """For a command output: which (``show_version``…)."""
    hostname: str | None
    device: str | None
    """The id of the configuration whose audit this file is part of; None if it is in none."""
    paired_by: How | None
    """``own`` (a configuration), ``hostname``, ``name``, ``hand`` or ``alone``."""
    note: str | None
    """Why it is left out of every audit, or audited alone."""


class DeviceOut(_Model):
    config: str
    """The configuration's file id."""
    name: str
    vendor: str | None
    hostname: str | None
    companions: tuple[str, ...]
    """The file ids of the command outputs audited with it."""


class PairingIn(_Model):
    config: uuid.UUID | None
    """The configuration to pair this command output with; null leaves it out of every audit."""


class UploadOut(_Model):
    id: str
    label: str | None
    state: UploadState
    frameworks: tuple[str, ...]
    vendor: str | None
    created_at: dt.datetime
    touched_at: dt.datetime
    started_at: dt.datetime | None
    accepted: int
    refused: int
    recognising: int
    """Accepted files not yet recognised; the upload can start when this is 0."""
    files: tuple[FileOut, ...]
    devices: tuple[DeviceOut, ...]


class FilesOut(_Model):
    files: tuple[FileOut, ...]
    """The rows this request added: one for a file, one per entry for a .zip."""


_RESPONSES: dict[int | str, dict[str, str]] = {
    404: {"description": "no such upload"},
    409: {"description": "the upload can't do that now (already started, say)"},
    503: {"description": "the database can't be reached"},
}


def _store(request: Request) -> UploadStore:
    store: UploadStore = request.app.state.uploads
    return store


async def _call[T](function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a blocking store call off the event loop, turning its errors into HTTP ones."""
    try:
        result = await run_in_threadpool(function, *args, **kwargs)
    except UploadNotFoundError:
        raise HTTPException(404, "no such upload") from None
    except FileNotInUploadError:
        raise HTTPException(404, "no such file in this upload") from None
    except PairingError as err:
        raise HTTPException(422, str(err)) from None
    except UploadStateError as err:
        raise HTTPException(409, str(err)) from None
    except SQLAlchemyError as err:
        log.exception("database unavailable", error=str(err))
        raise HTTPException(503, "database unavailable") from None
    return result


@router.post("", status_code=201, responses={422: {"description": "unknown framework or vendor"}})
async def create_upload(body: UploadIn, request: Request) -> UploadOut:
    kb = request.app.state.kb
    unknown = [f for f in body.frameworks if f not in kb.frameworks]
    if unknown:
        raise HTTPException(422, f"framework(s) not installed: {', '.join(unknown)}")
    if body.vendor is not None and body.vendor not in kb.vendor_packs:
        raise HTTPException(422, f"no vendor pack {body.vendor!r}")
    store = _store(request)
    upload_id: str = await _call(
        store.create,
        label=(body.label or "").strip() or None,
        frameworks=tuple(dict.fromkeys(body.frameworks)),
        vendor=body.vendor,
    )
    return await _get(store, upload_id)


@router.get("/{upload_id}", responses=_RESPONSES)
async def get_upload(upload_id: uuid.UUID, request: Request) -> UploadOut:
    return await _get(_store(request), str(upload_id))


@router.post(
    "/{upload_id}/files",
    status_code=201,
    responses={**_RESPONSES, 415: {"description": f"the body isn't {BODY_TYPE}"}},
)
async def add_file(upload_id: uuid.UUID, request: Request) -> FilesOut:
    media = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media != BODY_TYPE:
        raise HTTPException(415, f"send the file's bytes as {BODY_TYPE}")
    given = request.headers.get(FILE_NAME_HEADER)
    if given is None:
        raise HTTPException(422, f"the {FILE_NAME_HEADER} header names the file")
    store, uid = _store(request), str(upload_id)
    await _call(store.check_open, uid)
    name = display_name(unquote(given, errors="replace"))
    body = Received(new_id(), name, 0, None, type_refusal(name))
    if body.accepted:
        body = await _receive(request, store, uid, body)
    rows: list[Received] = (
        await run_in_threadpool(inspect, store.staging, uid, body) if body.accepted else [body]
    )
    recorded: list[Received] = await _call(store.add, uid, rows)
    _wake(request)
    view = await _get(store, uid)
    ids = {r.id for r in recorded}
    return FilesOut(files=tuple(f for f in view.files if f.id in ids))


@router.delete("/{upload_id}/files/{file_id}", status_code=204, responses=_RESPONSES)
async def remove_file(upload_id: uuid.UUID, file_id: uuid.UUID, request: Request) -> Response:
    found: bool = await _call(_store(request).remove_file, str(upload_id), str(file_id))
    if not found:
        raise HTTPException(404, "no such file in this upload")
    return Response(status_code=204)


@router.put(
    "/{upload_id}/files/{file_id}/pairing",
    responses={**_RESPONSES, 422: {"description": "the pairing can't be made; says why"}},
)
async def pair_file(
    upload_id: uuid.UUID, file_id: uuid.UUID, body: PairingIn, request: Request
) -> UploadOut:
    store, uid = _store(request), str(upload_id)
    config = None if body.config is None else str(body.config)
    await _call(store.pair, uid, str(file_id), config)
    return await _get(store, uid)


@router.delete("/{upload_id}/files/{file_id}/pairing", responses=_RESPONSES)
async def unpair_file(upload_id: uuid.UUID, file_id: uuid.UUID, request: Request) -> UploadOut:
    store, uid = _store(request), str(upload_id)
    await _call(store.unpair, uid, str(file_id))
    return await _get(store, uid)


@router.delete("/{upload_id}", status_code=204, responses=_RESPONSES)
async def discard_upload(upload_id: uuid.UUID, request: Request) -> Response:
    await _call(_store(request).discard, str(upload_id))
    return Response(status_code=204)


@router.post("/{upload_id}/start", status_code=202, responses=_RESPONSES)
async def start_upload(upload_id: uuid.UUID, request: Request) -> UploadOut:
    store, uid = _store(request), str(upload_id)
    await _call(store.start, uid)
    _wake(request)
    return await _get(store, uid)


# -- helpers ----------------------------------------------------------------------------------


def _wake(request: Request) -> None:
    """New jobs are queued: have the pool look now, not at its next poll."""
    pool = request.app.state.pool
    if pool is not None:
        pool.wake()


async def _get(store: UploadStore, upload_id: str) -> UploadOut:
    view: UploadView | None = await _call(store.get, upload_id)
    if view is None:
        raise HTTPException(404, "no such upload")
    files = tuple(_file(f) for f in view.files)
    accepted = sum(f.accepted for f in files)
    return UploadOut(
        id=view.id,
        label=view.label,
        state=view.state,
        frameworks=view.frameworks,
        vendor=view.vendor,
        created_at=view.created_at,
        touched_at=view.touched_at,
        started_at=view.started_at,
        accepted=accepted,
        refused=len(files) - accepted,
        recognising=view.recognising,
        files=files,
        devices=tuple(_device(d) for d in view.devices),
    )


def _file(f: FileView) -> FileOut:
    return FileOut(
        id=f.id,
        name=f.name,
        size=f.size,
        sha256=f.sha256,
        accepted=f.accepted,
        reason=f.reason,
        job_id=f.job_id,
        job_state=f.job_state,
        job_error=f.job_error,
        recognition=f.recognition,
        kind=None if f.recognised is None else f.recognised.kind,
        vendor=None if f.recognised is None else f.recognised.vendor,
        command=None if f.recognised is None else f.recognised.command,
        hostname=None if f.recognised is None else f.recognised.hostname,
        device=None if f.placement is None else f.placement.device,
        paired_by=None if f.placement is None else f.placement.how,
        note=None if f.placement is None else f.placement.note,
    )


def _device(d: DeviceView) -> DeviceOut:
    return DeviceOut(
        config=d.config,
        name=d.name,
        vendor=d.vendor,
        hostname=d.hostname,
        companions=d.companions,
    )


async def _receive(
    request: Request, store: UploadStore, upload_id: str, body: Received
) -> Received:
    """Stream the body into the file's ``.part``; the file as received, or refused as too large
    (reading stops at the limit, and what was written is deleted)."""
    limit = body_limit(body.name)
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return Received(body.id, body.name, int(declared), None, _too_large(limit))
    sink: RawIOBase = await run_in_threadpool(store.staging.create, upload_id, body.id)
    try:
        size, digest = await _copy(request.stream(), sink, limit)
    except _TooLargeError:
        await run_in_threadpool(sink.close)
        store.staging.remove(upload_id, body.id)
        return Received(body.id, body.name, limit, None, _too_large(limit))
    except BaseException:  # the client went away, or the disk is full
        await run_in_threadpool(sink.close)
        store.staging.remove(upload_id, body.id)
        raise
    await run_in_threadpool(sink.close)
    return Received(body.id, body.name, size, digest)


class _TooLargeError(Exception):
    pass


def _too_large(limit: int) -> str:
    return f"over the {limit // (1024 * 1024)} MiB limit"


async def _copy(chunks: AsyncIterator[bytes], sink: RawIOBase, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    pending: list[bytes] = []
    buffered = 0
    async for chunk in chunks:
        size += len(chunk)
        if size > limit:
            raise _TooLargeError
        digest.update(chunk)
        pending.append(chunk)
        buffered += len(chunk)
        if buffered >= CHUNK:
            await run_in_threadpool(sink.write, b"".join(pending))
            pending, buffered = [], 0
    if pending:
        await run_in_threadpool(sink.write, b"".join(pending))
    return size, digest.hexdigest()

"""Job routes (TODO M2.03): ``GET /api/jobs/{id}`` reports a job, and
``GET /api/jobs/{id}/result`` gives its result once it has succeeded (for an audit, the audit
result). Job ids are random UUIDs, not counters, so one job's id says nothing about another's.

A result is stored gzip-compressed (:mod:`kasauti.jobs.results`) and can expand to hundreds of
MiB, so it has its own route and is sent as stored, with ``Content-Encoding: gzip``, to any
client that accepts gzip (every browser, curl ``--compressed``, httpx); for any other it is
expanded as it is sent, a chunk at a time. Either way the server never holds the JSON text.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError

from kasauti.jobs import Job, JobQueue, JobState
from kasauti.jobs.results import expand
from kasauti.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


class JobOut(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    kind: str
    state: JobState
    attempts: int
    cancel_requested: bool
    created_at: dt.datetime
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    error: str | None
    """Why it failed, written to be shown; never configuration text."""
    has_result: bool
    """``GET /api/jobs/{id}/result`` has it."""


@router.get(
    "/{job_id}",
    responses={404: {"description": "no such job"}, 503: {"description": "database down"}},
)
def job(job_id: uuid.UUID, request: Request) -> JobOut:
    found = _get(request.app.state.jobs, job_id)
    return JobOut(
        id=found.id,
        kind=found.kind,
        state=found.state,
        attempts=found.attempts,
        cancel_requested=found.cancel_requested,
        created_at=found.created_at,
        started_at=found.started_at,
        finished_at=found.finished_at,
        error=found.error,
        has_result=found.has_result,
    )


@router.get(
    "/{job_id}/result",
    response_class=Response,
    responses={
        200: {"content": {"application/json": {}}, "description": "the result, as JSON"},
        404: {"description": "no such job"},
        409: {"description": "the job has no result (yet)"},
        503: {"description": "database down"},
    },
)
def job_result(job_id: uuid.UUID, request: Request) -> Response:
    queue: JobQueue = request.app.state.jobs
    found = _get(queue, job_id)
    try:
        blob = queue.result(found.id) if found.has_result else None
    except SQLAlchemyError as err:
        log.exception("database unavailable", error=str(err))
        raise HTTPException(503, "database unavailable") from None
    if blob is None:
        raise HTTPException(409, f"the job has no result; it is {found.state.value}")
    headers = {"Vary": "Accept-Encoding"}
    if accepts_gzip(request.headers.get("accept-encoding")):
        headers["Content-Encoding"] = "gzip"
        return Response(blob, media_type="application/json", headers=headers)
    return StreamingResponse(expand(blob), media_type="application/json", headers=headers)


def accepts_gzip(header: str | None) -> bool:
    """Whether an ``Accept-Encoding`` header accepts gzip (RFC 9110 §12.5.3): named, or ``*``,
    with a weight above zero; ``gzip;q=0`` refuses it even when ``*`` is accepted."""
    weights: dict[str, float] = {}
    for item in (header or "").split(","):
        coding, _, params = item.partition(";")
        weight = 1.0
        for param in params.split(";"):
            name, _, value = param.partition("=")
            if name.strip().lower() == "q":
                try:
                    weight = float(value)
                except ValueError:
                    weight = 0.0
        weights[coding.strip().lower()] = weight
    for coding in ("gzip", "x-gzip", "*"):
        if coding in weights:
            return weights[coding] > 0
    return False


def _get(queue: JobQueue, job_id: uuid.UUID) -> Job:
    try:
        found = queue.get(str(job_id))
    except SQLAlchemyError as err:
        log.exception("database unavailable", error=str(err))
        raise HTTPException(503, "database unavailable") from None
    if found is None:
        raise HTTPException(404, "no such job")
    return found

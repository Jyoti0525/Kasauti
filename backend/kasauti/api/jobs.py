"""Job routes (TODO M2.03): ``GET /api/jobs/{id}`` reports a job, and its result once it has
succeeded (for an audit, the audit result). Job ids are random UUIDs, not counters, so one
job's id says nothing about another's."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError

from kasauti.jobs import JobQueue, JobState
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
    result: dict[str, Any] | None


@router.get(
    "/{job_id}",
    responses={404: {"description": "no such job"}, 503: {"description": "database down"}},
)
def job(job_id: uuid.UUID, request: Request) -> JobOut:
    queue: JobQueue = request.app.state.jobs
    try:
        found = queue.get(str(job_id))
    except SQLAlchemyError as err:
        log.exception("database unavailable", error=str(err))
        raise HTTPException(503, "database unavailable") from None
    if found is None:
        raise HTTPException(404, "no such job")
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
        result=found.result,
    )

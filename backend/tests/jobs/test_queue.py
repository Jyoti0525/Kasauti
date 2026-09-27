"""The job queue's database operations, on SQLite and PostgreSQL (TODO M2.03)."""

from __future__ import annotations

import datetime as dt
import threading

import pytest
from sqlalchemy import Engine, select, update
from sqlalchemy.exc import StatementError

from kasauti.jobs import JobInputError, JobQueue, JobState
from kasauti.jobs import queue as queue_module
from kasauti.jobs.child import ERROR_LIMIT
from kasauti.jobs.queue import PAYLOAD_LIMIT
from kasauti.jobs.results import decode_result, encode_result
from kasauti.jobs.table import jobs

T0 = dt.datetime(2026, 9, 26, 12, 0, tzinfo=dt.UTC)
LEASE = dt.timedelta(seconds=60)


@pytest.fixture
def queue(any_engine: Engine) -> JobQueue:
    return JobQueue(any_engine, {"a", "b"})


@pytest.mark.parametrize(
    ("kind", "payload", "problem"),
    [
        ("nope", {}, "unknown job kind 'nope'"),
        ("a", ["not", "an", "object"], "a JSON object"),
        ("a", {"x": float("nan")}, r"isn't JSON \(ValueError\)"),
        ("a", {"x": object()}, r"isn't JSON \(TypeError\)"),
        ("a", {"config": "x" * PAYLOAD_LIMIT}, "pass a reference to stored input"),
    ],
)
def test_what_cant_be_queued(queue: JobQueue, kind: str, payload: object, problem: str) -> None:
    with pytest.raises(JobInputError, match=problem):
        queue.enqueue(kind, payload)  # type: ignore[arg-type]
    assert queue.pending() == 0


def test_limits_must_be_positive(queue: JobQueue) -> None:
    with pytest.raises(JobInputError):
        queue.enqueue("a", {}, timeout_s=0)
    with pytest.raises(JobInputError):
        queue.enqueue("a", {}, max_attempts=0)


def test_a_queued_job(queue: JobQueue) -> None:
    job_id = queue.enqueue("a", {"upload": "sha256:ab", "n": 1}, now=T0)
    job = queue.get(job_id)
    assert job is not None
    assert (job.kind, job.state, job.attempts, job.has_result, job.error) == (
        "a",
        JobState.QUEUED,
        0,
        False,
        None,
    )
    assert queue.result(job_id) is None
    assert job.created_at == T0  # comes back aware, in UTC
    assert job.created_at.tzinfo is dt.UTC
    assert queue.get("00000000-0000-4000-8000-000000000000") is None


def test_a_naive_time_is_refused_not_guessed(queue: JobQueue) -> None:
    with pytest.raises(StatementError, match="naive datetime"):
        queue.enqueue("a", {}, now=dt.datetime(2026, 9, 26, 12, 0))


def test_claims_take_the_oldest_first_and_only_known_kinds(any_engine: Engine) -> None:
    other = JobQueue(any_engine, {"c"})
    other.enqueue("c", {}, now=T0)
    queue = JobQueue(any_engine, {"a"})
    ids = [queue.enqueue("a", {"i": i}, now=T0 + dt.timedelta(seconds=i)) for i in (2, 0, 1)]
    claimed = queue.claim("w1", 2, now=T0)
    assert [c.id for c in claimed] == [ids[1], ids[2]]
    assert [c.payload for c in claimed] == ['{"i":0}', '{"i":1}']
    assert [c.id for c in queue.claim("w1", 5, now=T0)] == [ids[0]]
    assert queue.claim("w1", 5, now=T0) == []  # "c" isn't this queue's to run
    job = queue.get(ids[1])
    assert job is not None
    assert (job.state, job.attempts, job.started_at) == (JobState.RUNNING, 1, T0)


def test_concurrent_pools_never_claim_the_same_job(any_engine: Engine) -> None:
    queue = JobQueue(any_engine, {"a"})
    ids = {queue.enqueue("a", {"i": i}) for i in range(40)}
    got: dict[str, list[str]] = {}

    def pool(name: str) -> None:
        mine = got.setdefault(name, [])
        while claims := JobQueue(any_engine, {"a"}).claim(name, 3):
            mine += [c.id for c in claims]

    threads = [threading.Thread(target=pool, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    every = [job_id for claimed in got.values() for job_id in claimed]
    assert sorted(every) == sorted(ids)  # each claimed exactly once


def test_only_the_holder_records_the_outcome(queue: JobQueue) -> None:
    job_id = queue.enqueue("a", {})
    queue.claim("w1", 1)
    result = encode_result({"x": 1})
    assert not queue.finish("w2", job_id, JobState.SUCCEEDED, result=result)
    assert queue.finish("w1", job_id, JobState.SUCCEEDED, result=result)
    assert not queue.finish("w1", job_id, JobState.FAILED, error="again")  # already finished
    job = queue.get(job_id)
    assert job is not None
    assert (job.state, job.has_result, job.error) == (JobState.SUCCEEDED, True, None)
    stored = queue.result(job_id)
    assert stored == result
    assert decode_result(stored) == {"x": 1}
    with pytest.raises(ValueError, match="finished state"):
        queue.finish("w1", job_id, JobState.RUNNING)


def test_a_result_over_the_limit_is_refused(
    queue: JobQueue, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(queue_module, "RESULT_LIMIT", 10)
    job_id = queue.enqueue("a", {})
    queue.claim("w1", 1)
    with pytest.raises(ValueError, match="over 10 bytes compressed"):
        queue.finish("w1", job_id, JobState.SUCCEEDED, result=bytes(11))
    job = queue.get(job_id)
    assert job is not None
    assert job.state is JobState.RUNNING


def test_errors_are_capped(queue: JobQueue) -> None:
    job_id = queue.enqueue("a", {})
    queue.claim("w1", 1)
    queue.finish("w1", job_id, JobState.FAILED, error="e" * 5000)
    job = queue.get(job_id)
    assert job is not None
    assert job.error == "e" * ERROR_LIMIT


def test_cancelling(queue: JobQueue) -> None:
    done = queue.enqueue("a", {}, now=T0)
    running = queue.enqueue("a", {}, now=T0 + dt.timedelta(seconds=1))
    queue.claim("w1", 2)
    queue.finish("w1", done, JobState.SUCCEEDED, result=encode_result({}))
    queued = queue.enqueue("a", {})

    job = queue.cancel(queued)
    assert job is not None
    assert (job.state, job.finished_at is not None) == (JobState.CANCELLED, True)

    job = queue.cancel(running)  # the pool stops it at its next heartbeat
    assert job is not None
    assert (job.state, job.cancel_requested) == (JobState.RUNNING, True)
    assert queue.heartbeat("w1", [running]) == (set(), {running})

    job = queue.cancel(done)  # finished: left alone
    assert job is not None
    assert (job.state, job.cancel_requested) == (JobState.SUCCEEDED, False)
    assert queue.cancel("00000000-0000-4000-8000-000000000000") is None


def test_a_heartbeat_reports_jobs_taken_over(queue: JobQueue, any_engine: Engine) -> None:
    job_id = queue.enqueue("a", {})
    queue.claim("w1", 1, now=T0)
    assert queue.heartbeat("w1", [job_id], now=T0 + LEASE / 2) == (set(), set())
    with any_engine.begin() as conn:
        conn.execute(update(jobs).values(worker="w2"))
    assert queue.heartbeat("w1", [job_id]) == ({job_id}, set())
    with any_engine.connect() as conn:
        beat = conn.execute(select(jobs.c.heartbeat_at)).scalar_one()
    assert beat == T0 + LEASE / 2  # w1's late heartbeat didn't touch w2's job


def test_jobs_of_a_lost_pool_are_recovered(queue: JobQueue) -> None:
    fresh, stale, spent, cancelled = (
        queue.enqueue("a", {}, max_attempts=2, now=T0 + dt.timedelta(seconds=i)) for i in range(4)
    )
    queue.claim("dead", 4, now=T0)
    with queue.engine.begin() as conn:  # `spent` was already lost once: attempt 2 of 2
        conn.execute(update(jobs).where(jobs.c.id == spent).values(attempts=2))
    queue.cancel(cancelled)
    queue.heartbeat("dead", [fresh], now=T0 + LEASE)  # only `fresh` is still being renewed

    recovered = queue.recover(LEASE, now=T0 + LEASE + dt.timedelta(seconds=1))
    assert sorted(recovered) == sorted([stale, spent, cancelled])
    states = {i: queue.get(i) for i in (fresh, stale, spent, cancelled)}
    assert {i: j.state for i, j in states.items() if j} == {
        fresh: JobState.RUNNING,
        stale: JobState.QUEUED,
        spent: JobState.FAILED,
        cancelled: JobState.CANCELLED,
    }
    requeued = states[stale]
    assert requeued is not None
    assert requeued.attempts == 1  # the lost attempt counts
    failed = states[spent]
    assert failed is not None
    assert failed.error == "the worker running it was lost on every attempt"


def test_released_jobs_go_back_without_losing_an_attempt(queue: JobQueue) -> None:
    job_id = queue.enqueue("a", {})
    queue.claim("w1", 1)
    assert queue.release("w2", [job_id]) == 0  # not w2's
    assert queue.release("w1", [job_id]) == 1
    job = queue.get(job_id)
    assert job is not None
    assert (job.state, job.attempts, job.started_at) == (JobState.QUEUED, 0, None)

"""The worker pool, with real worker processes (TODO M2.03)."""

from __future__ import annotations

import datetime as dt
import os
import pickle
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, select, update

from kasauti.jobs import JobQueue, JobState, WorkerPool
from kasauti.jobs.pool import _CONTEXT, _Running
from kasauti.jobs.table import jobs


@pytest.fixture
def queue(engine: Engine, handlers: dict[str, str]) -> JobQueue:
    return JobQueue(engine, handlers)


@pytest.fixture
def pool(queue: JobQueue, handlers: dict[str, str]) -> Iterator[WorkerPool]:
    pool = WorkerPool(queue, handlers, workers=2, poll_s=0.05, heartbeat_s=0.0, grace_s=0.0)
    yield pool
    pool.stop()
    pool._drain(grace_s=0)  # a test that stopped half-way leaves no process behind


def _run(
    queue: JobQueue,
    pool: WorkerPool,
    kind: str,
    payload: dict[str, object] | None = None,
    **kw: int,
) -> tuple[str, JobState, str | None, dict[str, object] | None]:
    job_id = queue.enqueue(kind, payload or {}, **kw)
    pool.run_until_idle(timeout_s=60)
    job = queue.get(job_id)
    assert job is not None
    return job_id, job.state, job.error, job.result


def _until(check: Callable[[], bool], pool: WorkerPool | None, timeout_s: float = 30) -> None:
    """Wait for ``check``, driving ``pool`` meanwhile (``None``: its own thread drives it)."""
    deadline = time.monotonic() + timeout_s
    while not check():
        assert time.monotonic() < deadline, "timed out waiting"
        if pool is not None:
            pool.tick()
        time.sleep(0.02)


def test_the_pool_and_the_queue_must_agree(engine: Engine, handlers: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="differ"):
        WorkerPool(JobQueue(engine, {"echo"}), handlers)
    with pytest.raises(ValueError, match="isn't 'module:function'"):
        WorkerPool(JobQueue(engine, {"x"}), {"x": "os.system"})
    with pytest.raises(TypeError, match="isn't a function"):
        WorkerPool(JobQueue(engine, {"x"}), {"x": "os:sep"})
    with pytest.raises(ValueError, match="at least one worker"):
        WorkerPool(JobQueue(engine, handlers), handlers, workers=0)


def test_a_job_runs_in_its_own_process(queue: JobQueue, pool: WorkerPool) -> None:
    _, state, error, result = _run(queue, pool, "echo", {"upload": "sha256:ab"})
    assert (state, error) == (JobState.SUCCEEDED, None)
    assert result is not None
    assert result["echo"] == {"upload": "sha256:ab"}
    assert result["pid"] != os.getpid()


def test_a_handler_s_own_message_is_shown(queue: JobQueue, pool: WorkerPool) -> None:
    _, state, error, _ = _run(queue, pool, "refuse")
    assert (state, error) == (JobState.FAILED, "not a configuration file")


def test_other_exceptions_are_recorded_by_type_only(
    queue: JobQueue, pool: WorkerPool, engine: Engine
) -> None:
    job_id, state, error, _ = _run(queue, pool, "leak")
    assert (state, error) == (JobState.FAILED, "the job failed with an internal error (ValueError)")
    with engine.connect() as conn:
        row = conn.execute(select(jobs).where(jobs.c.id == job_id)).one()
    assert "PLACEHOLDER" not in repr(row)  # the configuration text never reaches the database


def test_a_crash_fails_only_its_own_job(queue: JobQueue, pool: WorkerPool) -> None:
    _, state, error, _ = _run(queue, pool, "crash")
    assert (state, error) == (JobState.FAILED, "the worker process ended unexpectedly (exit 3)")
    _, state, _, _ = _run(queue, pool, "echo")
    assert state is JobState.SUCCEEDED


def test_a_hung_job_is_stopped_at_its_time_limit(queue: JobQueue, pool: WorkerPool) -> None:
    started = time.monotonic()
    _, state, error, _ = _run(queue, pool, "sleep", {"s": 60}, timeout_s=1)
    assert (state, error) == (JobState.FAILED, "timed out after 1 s")
    assert time.monotonic() - started < 30


@pytest.mark.parametrize(
    ("kind", "error"),
    [
        ("huge", "the result is over 8388608 bytes"),
        ("not_json", "the job failed with an internal error (TypeError)"),
        ("not_object", "the job returned something other than an object"),
    ],
)
def test_results_must_be_small_json_objects(
    queue: JobQueue, pool: WorkerPool, kind: str, error: str
) -> None:
    assert _run(queue, pool, kind)[1:3] == (JobState.FAILED, error)


def test_what_a_worker_sends_back_is_never_unpickled(
    queue: JobQueue, pool: WorkerPool, tmp_path: Path
) -> None:
    """A worker a hostile file has taken over could send anything. A pickle that would create a
    file when loaded is recorded as unreadable, and the file is never created."""
    marker = tmp_path / "pwned"

    class Payload:
        def __reduce__(self) -> tuple[object, tuple[str, str]]:
            return (open, (str(marker), "w"))

    job_id = queue.enqueue("echo", {})
    (claim,) = queue.claim(pool.name, 1)
    receive, send = _CONTEXT.Pipe(duplex=False)
    send.send_bytes(pickle.dumps(Payload()))
    send.close()
    process = _CONTEXT.Process(target=time.sleep, args=(0,))
    process.start()
    process.join()
    pool._read(_Running(claim, process, receive, deadline=time.monotonic() + 60))

    job = queue.get(job_id)
    assert job is not None
    assert (job.state, job.error) == (JobState.FAILED, "the worker sent an unreadable result")
    assert not marker.exists()


def test_jobs_run_side_by_side_up_to_the_pool_size(queue: JobQueue, pool: WorkerPool) -> None:
    ids = [queue.enqueue("sleep", {"s": 60}, timeout_s=120) for _ in range(3)]
    pool.tick()
    assert sorted(pool.running) == sorted(ids[:2])
    assert queue.get(ids[2]).state is JobState.QUEUED  # type: ignore[union-attr]


def test_a_running_job_can_be_cancelled(queue: JobQueue, pool: WorkerPool) -> None:
    job_id = queue.enqueue("sleep", {"s": 60}, timeout_s=120)
    pool.tick()
    assert pool.running == (job_id,)
    queue.cancel(job_id)
    _until(lambda: not pool.running, pool)
    job = queue.get(job_id)
    assert job is not None
    assert (job.state, job.error) == (JobState.CANCELLED, "cancelled while running")


def test_a_job_taken_over_elsewhere_is_stopped_here(
    queue: JobQueue, pool: WorkerPool, engine: Engine
) -> None:
    job_id = queue.enqueue("sleep", {"s": 60}, timeout_s=120)
    pool.tick()
    with engine.begin() as conn:  # another pool recovered it after this one's lease ran out
        conn.execute(update(jobs).values(worker="elsewhere"))
    _until(lambda: not pool.running, pool)  # its process stopped at the next heartbeat
    job = queue.get(job_id)
    assert job is not None
    assert job.state is JobState.RUNNING  # the other pool's to finish; untouched here


def test_a_lost_pool_s_jobs_are_run_by_another(
    queue: JobQueue, handlers: dict[str, str], engine: Engine
) -> None:
    job_id = queue.enqueue("echo", {})
    queue.claim("a pool that died", 1)
    with engine.begin() as conn:
        conn.execute(update(jobs).values(heartbeat_at=dt.datetime(2000, 1, 1, tzinfo=dt.UTC)))
    WorkerPool(queue, handlers, workers=1, poll_s=0.05).run_until_idle(timeout_s=60)
    job = queue.get(job_id)
    assert job is not None
    assert (job.state, job.attempts) == (JobState.SUCCEEDED, 2)


def test_in_the_background_and_back_to_the_queue_at_shutdown(
    queue: JobQueue, pool: WorkerPool
) -> None:
    pool.start()
    with pytest.raises(RuntimeError, match="already running"):
        pool.start()
    quick = queue.enqueue("echo", {})
    pool.wake()
    _until(lambda: queue.get(quick).state is JobState.SUCCEEDED, None)  # type: ignore[union-attr]

    slow = queue.enqueue("sleep", {"s": 60}, timeout_s=120)
    pool.wake()
    _until(lambda: queue.get(slow).state is JobState.RUNNING, None)  # type: ignore[union-attr]
    pool.stop()  # grace 0: stopped and handed back, attempt not counted
    job = queue.get(slow)
    assert job is not None
    assert (job.state, job.attempts) == (JobState.QUEUED, 0)
    assert pool.running == ()
